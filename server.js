/**
 * PreçoCerto — Backend v8
 * ════════════════════════════════════════════════════════════
 * MUDANÇAS v8 (em relação ao v1 que estava em produção):
 *   1. MongoDB Atlas real via Mongoose — dados PERSISTEM entre reinícios
 *   2. Todas as 30+ rotas que o frontend chama agora existem
 *   3. Promoções: DELETE real no banco (não mais só in-memory)
 *   4. Aprovação de solicitação: gera credenciais + link WhatsApp
 *   5. Login de mercado: bcrypt correto (antes comparava texto puro)
 *   6. Gestão completa de clientes: editar dados + alterar senha pelo admin
 *   7. Blacklist: número bloqueado 2 meses após exclusão de conta
 *   8. Produtos novos: Café Piatã, Café Rigno, Papel Higiênico Paloma
 *   9. Seed automático ao conectar no banco vazio
 *  10. Cron 24h limpa blacklist vencida
 * ════════════════════════════════════════════════════════════
 * Variáveis de ambiente (Render):
 *   MONGODB_URI   → connection string do Atlas  [OBRIGATÓRIO]
 *   JWT_SECRET    → chave de assinatura JWT     [OBRIGATÓRIO]
 *   APP_URL       → URL do app no Render        (para links WhatsApp/email)
 *   GEMINI_API_KEY → IA para análise de fotos   (opcional)
 *   RESEND_API_KEY → e-mail transacional        (opcional)
 *   EMAIL_FROM     → remetente dos e-mails      (opcional)
 */

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const mongoose  = require('mongoose');
const path      = require('path');
const crypto    = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET     = process.env.JWT_SECRET     || 'precocerto_dev_secret_v8_mude_em_producao';
const MONGODB_URI    = process.env.MONGODB_URI     || '';
const APP_URL        = process.env.APP_URL         || 'https://precocerto.onrender.com';
const GEMINI_KEY     = process.env.GEMINI_API_KEY  || '';
const RESEND_KEY     = process.env.RESEND_API_KEY  || '';
const EMAIL_FROM     = process.env.EMAIL_FROM      || 'PreçoCerto <noreply@resend.dev>';

app.set('trust proxy', 1);

// ═══════════════════════════════════════════════════════════
// MONGODB
// ═══════════════════════════════════════════════════════════
if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(async () => {
      console.log('✅ MongoDB Atlas conectado!');

      // Corrige índice email legado: converte para sparse (permite múltiplos null/vazio)
      try {
        const collection = mongoose.connection.collection('clientes');
        const indexes = await collection.indexes();
        const emailIdx = indexes.find(i => i.key && i.key.email !== undefined);
        if (emailIdx && emailIdx.unique && !emailIdx.sparse) {
          await collection.dropIndex('email_1');
          await collection.createIndex({ email: 1 }, { unique: true, sparse: true, background: true });
          console.log('[DB] Índice email_1 convertido para sparse (permite múltiplos null)');
        }
      } catch(idxErr) {
        console.warn('[DB] Aviso ao corrigir índice email:', idxErr.message);
      }

      setTimeout(seedInicial, 2000);
      setTimeout(agendarFilaIA, 5000); // Agenda processamento da fila às 2h da manhã
      // Limpar blacklist vencida a cada 24h
      // Limpa blacklist vencida a cada 24h
      setInterval(async () => {
        const r = await Blacklist.updateMany(
          { dataVencimento: { $lte: new Date() }, ativo: true }, { ativo: false }
        );
        if (r.modifiedCount) console.log('[Blacklist] ' + r.modifiedCount + ' entradas expiradas');
      }, 24 * 60 * 60 * 1000);

      // Limpeza automática de logs e solicitações a cada 48h
      const limparDados48h = async () => {
        try {
          const limite48h = new Date(Date.now() - 48 * 60 * 60 * 1000);
          const limite7d  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          // Logs comuns: remove após 48h / Logs admin+auth: remove após 7 dias
          const rLogs = await Log.deleteMany({
            $or: [
              { tipo: { $nin: ['admin','auth'] }, createdAt: { $lt: limite48h } },
              { tipo: { $in: ['admin','auth'] },  createdAt: { $lt: limite7d  } }
            ]
          });
          // Solicitações aprovadas/recusadas: remove após 48h
          const rSolic = await Solicitacao.deleteMany({
            status: { $in: ['Aprovado','Recusado'] },
            updatedAt: { $lt: limite48h }
          });

          // Desativar promoções com validade vencida (formato DD/MM/YYYY)
          const todasPromos = await Promocao.find({ ativa: true });
          const hoje = new Date(); hoje.setHours(0,0,0,0);
          const idsExpirados = todasPromos
            .filter(p => {
              const partes = (p.validade||'').split('/');
              if (partes.length !== 3) return false;
              const [dd,mm,yyyy] = partes.map(Number);
              return new Date(yyyy, mm-1, dd) < hoje;
            })
            .map(p => p._id);
          let rPromos = { modifiedCount: 0 };
          if (idsExpirados.length) {
            rPromos = await Promocao.updateMany({ _id: { $in: idsExpirados } }, { ativa: false });
          }

          console.log('[Limpeza 48h] logs: ' + rLogs.deletedCount + ', solicitacoes: ' + rSolic.deletedCount + ', promos expiradas: ' + rPromos.modifiedCount);
        } catch(e) {
          console.error('Erro limpeza automatica:', e.message);
        }
      };
      setTimeout(limparDados48h, 10000); // roda 10s após start
      setInterval(limparDados48h, 48 * 60 * 60 * 1000); // repete a cada 48h

    })
    .catch(e => console.error('[MongoDB] Erro conexao:', e.message));
} else {
  console.warn('⚠️  MONGODB_URI não definida — DADOS NÃO PERSISTEM entre reinícios!');
}

// ═══════════════════════════════════════════════════════════
// SCHEMAS
// ═══════════════════════════════════════════════════════════
const AdminSchema = new mongoose.Schema({
  usuario:   { type: String, required: true, unique: true, trim: true },
  senhaHash: { type: String, required: true },
  nome:      { type: String, required: true },
  email:     { type: String, default: '' },
  nivel:     { type: String, default: 'admin' }, // super | admin | moderador
  ativo:     { type: Boolean, default: true },
}, { timestamps: true });

const ClienteSchema = new mongoose.Schema({
  nome:                    { type: String, required: true, trim: true },
  login:                   { type: String, required: true, unique: true, lowercase: true, trim: true },
  senhaHash:               { type: String, required: true },
  email:                   { type: String, default: null, trim: true, sparse: true },
  telefone:                { type: String, required: true, unique: true },
  bairro:                  { type: String, default: '' },
  notifWhats:              { type: Boolean, default: false },
  bloqueado:               { type: Boolean, default: false },
  banPermanente:           { type: Boolean, default: false },
  banTemporario:           { type: String, default: null },
  motivoBloqueio:          { type: String, default: '' },
  emailVerificado:         { type: Boolean, default: true },
  errosConsecutivos:       { type: Number, default: 0 },
  totalContribuicoes:      { type: Number, default: 0 },
  contribuicoesRejeitadas: { type: Number, default: 0 },
  ip:                      { type: String, default: '' },
  dataCadastro:            { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
}, { timestamps: true });

const MercadoSchema = new mongoose.Schema({
  nome:      { type: String, required: true },
  icone:     { type: String, default: '🏪' },
  endereco:  { type: String, default: '' },
  bairro:    { type: String, default: 'Centro' },
  cidade:    { type: String, default: 'Piatã' },
  whatsapp:  { type: String, default: '' },
  website:   { type: String, default: null },
  parceiro:  { type: Boolean, default: false },
  plano:     { type: String, default: null },
  usuario:   { type: String, default: null },
  senhaHash: { type: String, default: null },
  lat:       { type: Number, default: null },
  lng:       { type: Number, default: null },
  plusCode:  { type: String, default: null },
  nomeGoogleMaps: { type: String, default: null },
  ativo:     { type: Boolean, default: true },
}, { timestamps: true });

const ProdutoSchema = new mongoose.Schema({
  nome:      { type: String, required: true },
  emoji:     { type: String, default: '📦' },
  categoria: { type: String, default: 'Geral' },
  ativo:     { type: Boolean, default: true },
}, { timestamps: true });

const PrecoSchema = new mongoose.Schema({
  produtoId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Produto', required: true },
  mercadoId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  preco:       { type: Number, required: true },
  dataAtu:     { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  fonte:       { type: String, default: 'admin' },
  autor:       { type: String, default: 'Admin' },
}, { timestamps: true });
PrecoSchema.index({ produtoId: 1, mercadoId: 1 });

const PromocaoSchema = new mongoose.Schema({
  produtoId:   { type: mongoose.Schema.Types.Mixed },
  mercadoId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  precoNormal: { type: Number, required: true },
  precoPromo:  { type: Number, required: true },
  descricao:   { type: String, default: '' },
  validade:    { type: String, required: true },
  ativa:       { type: Boolean, default: true },
}, { timestamps: true });

const ContribuicaoSchema = new mongoose.Schema({
  tipo:         { type: String, default: 'texto' },
  produtoId:    { type: mongoose.Schema.Types.Mixed },
  mercadoId:    { type: mongoose.Schema.Types.Mixed },
  preco:        { type: Number },
  autor:        { type: String, default: 'Anônimo' },
  clienteId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', default: null },
  status:       { type: String, default: 'pendente' }, // pendente | aprovado | rejeitado
  motivoRecusa: { type: String, default: '' },
  obs:          { type: String, default: '' },
  fotoUrl:      { type: String, default: null },
  ip:           { type: String, default: '' },
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
}, { timestamps: true });

const LogSchema = new mongoose.Schema({
  tipo:        { type: String, required: true },
  descricao:   { type: String, required: true },
  usuario:     { type: String, default: 'anon' },
  ip:          { type: String, default: '' },
  data:        { type: String, default: () => new Date().toLocaleString('pt-BR') },
  // Campos extras para solicitações de produto
  mercadoId:   { type: String, default: '' },
  mercadoNome: { type: String, default: '' },
  preco:       { type: Number, default: 0 },
  nomeProduto: { type: String, default: '' },
}, { timestamps: true });

const ConfigSchema = new mongoose.Schema({
  chave: { type: String, required: true, unique: true },
  valor: { type: mongoose.Schema.Types.Mixed, required: true },
}, { timestamps: true });

const SolicitacaoSchema = new mongoose.Schema({
  mercado:     { type: String, required: true },
  responsavel: { type: String, required: true },
  whatsapp:    { type: String, required: true },
  email:       { type: String, default: '' },
  loginDesejado: { type: String, default: '' },
  senhaDesejada: { type: String, default: '' },
  endereco:    { type: String, default: '' },
  bairro:      { type: String, default: '' },
  plano:       { type: String, required: true },
  status:      { type: String, default: 'Pendente' }, // Pendente | Aprovado | Recusado
  mercadoId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', default: null },
  credenciais: { type: Object, default: null },
  data:        { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
}, { timestamps: true });

const OcorrenciaSchema = new mongoose.Schema({
  cliente:      { type: String, default: 'Visitante' },
  clienteLogin: { type: String, default: null },
  whatsapp:     { type: String, default: null },
  mensagem:     { type: String, required: true },
  historico:    { type: String, default: null },
  tipo:         { type: String, default: 'suporte' },
  tela:         { type: String, default: null },
  reproduz:     { type: String, default: null },
  conversa:     { type: Array,  default: [] },
  fotoBase64:   { type: String, default: null },
  status:       { type: String, default: 'aberto' },
  abertaPor:    { type: String, default: null },
  abertaEm:     { type: Date,   default: null },
  expiraEm:     { type: Date,   default: null },
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  hora:         { type: String, default: () => new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}) },
}, { timestamps: true });

const ChatMsgSchema = new mongoose.Schema({
  clienteId:    { type: String, required: true },
  tipo:         { type: String, required: true }, // user | bot | admin | sistema
  texto:        { type: String, required: true },
  hora:         { type: String, required: true },
  lida:         { type: Boolean, default: false },
  dadosCliente: { type: Object, default: null }, // preenchido quando cliente escala ou sai
}, { timestamps: true });

const BlacklistSchema = new mongoose.Schema({
  telefone:       { type: String, required: true, unique: true },
  dataInicio:     { type: Date, default: Date.now },
  dataVencimento: { type: Date, required: true },
  motivo:         { type: String, default: 'Excluído por administrador' },
  criadoPor:      { type: String, default: 'admin' },
  ativo:          { type: Boolean, default: true },
}, { timestamps: true });

// ═══════════════════════════════════════════════════════════
// MODELOS
// ═══════════════════════════════════════════════════════════
const Admin        = mongoose.model('Admin',        AdminSchema);
const Cliente      = mongoose.model('Cliente',      ClienteSchema);
const Mercado      = mongoose.model('Mercado',      MercadoSchema);
const Produto      = mongoose.model('Produto',      ProdutoSchema);
const Preco        = mongoose.model('Preco',        PrecoSchema);
const Promocao     = mongoose.model('Promocao',     PromocaoSchema);
const Contribuicao = mongoose.model('Contribuicao', ContribuicaoSchema);
const Log          = mongoose.model('Log',          LogSchema);
const Config       = mongoose.model('Config',       ConfigSchema);
const Solicitacao  = mongoose.model('Solicitacao',  SolicitacaoSchema);
const Ocorrencia   = mongoose.model('Ocorrencia',   OcorrenciaSchema);
const ChatMsg      = mongoose.model('ChatMsg',      ChatMsgSchema);
const Blacklist    = mongoose.model('Blacklist',    BlacklistSchema);

// ── FILA IA ────────────────────────────────────────────────────────
const FilaIASchema = new mongoose.Schema({
  clienteId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', default: null },
  clienteLogin: { type: String, default: '' },
  mercadoId:    { type: mongoose.Schema.Types.Mixed, required: true },
  mercadoNome:  { type: String, default: '' },
  imagemBase64: { type: String, required: true }, // base64 da foto (TTL 48h)
  mediaType:    { type: String, default: 'image/jpeg' },
  status:       { type: String, default: 'aguardando' }, // aguardando|processando|concluido|erro
  tentativas:   { type: Number, default: 0 },
  erroMsg:      { type: String, default: '' },
  resultado:    { type: mongoose.Schema.Types.Mixed, default: null }, // JSON extraído pela IA
  processadaEm: { type: Date, default: null },
  expiraEm:     { type: Date, default: () => new Date(Date.now() + 48*60*60*1000) }, // TTL 48h
}, { timestamps: true });
const FilaIA = mongoose.model('FilaIA', FilaIASchema);

// ── CACHE IA (hash de imagem → resultado) ────────────────────
const CacheIASchema = new mongoose.Schema({
  hashImagem:  { type: String, required: true, unique: true, index: true },
  resultado:   { type: mongoose.Schema.Types.Mixed, required: true }, // JSON com itens extraídos
  usos:        { type: Number, default: 1 },
  expiraEm:    { type: Date, default: () => new Date(Date.now() + 90*24*60*60*1000) }, // TTL 90 dias
}, { timestamps: true });
CacheIASchema.index({ expiraEm: 1 }, { expireAfterSeconds: 0 }); // MongoDB deleta automaticamente
const CacheIA = mongoose.model('CacheIA', CacheIASchema);

// Hash leve: primeiros+últimos 500 chars do base64 + tamanho
function hashBase64Leve(b64) {
  const s = String(b64||'');
  const sample = s.slice(0,500) + '|' + s.slice(-500) + '|' + s.length;
  let h = 0;
  for(let i=0;i<sample.length;i++){ h = ((h<<5)-h) + sample.charCodeAt(i); h|=0; }
  return 'ia_' + Math.abs(h).toString(36) + '_' + s.length;
}

// ═══════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════
// ── CORS RESTRITO ──────────────────────────────────────────
const ALLOWED_ORIGINS = [
  process.env.APP_URL || 'https://precocerto.onrender.com',
  'http://localhost:3000',
  'http://localhost:5173',
];
app.use(cors({
  origin: (origin, cb) => {
    // Sem origin = app mobile, PWA instalado, Postman — permite
    if (!origin) return cb(null, true);
    // Permite qualquer subdomínio .onrender.com (PWA pode ter URL ligeiramente diferente)
    if (origin.endsWith('.onrender.com')) return cb(null, true);
    // Permite localhost em qualquer porta
    if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) return cb(null, true);
    // Permite origens explicitamente na lista
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Loga origem bloqueada para debug
    console.warn('[CORS bloqueado]', origin);
    cb(new Error('CORS: origem nao permitida: ' + origin));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
}));

// ── HELMET ──────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // CSP gerenciado pelo frontend
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// ── JSON BODY ───────────────────────────────────────────────
app.use(express.json({ limit: '12mb' }));

// ── SANITIZADOR ─────────────────────────────────────────────
function sanitize(str, maxLen=500) {
  if (typeof str !== 'string') return str;
  return str.trim().substring(0, maxLen).replace(/[<>]/g,'').replace(/ /g,'');
}

// ── VALIDAR PRECO ───────────────────────────────────────────
function validarPreco(p) {
  const n = parseFloat(p);
  return !isNaN(n) && n > 0 && n < 99999;
}
app.use(express.urlencoded({ extended: true }));
app.use((req,res,next)=>{res.setHeader('Cache-Control','no-cache,no-store,must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Expires','0');next();});
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (/\.(png|webp|ico)$/.test(filePath))
      res.setHeader('Cache-Control', 'public, max-age=86400');
    if (filePath.endsWith('manifest.json'))
      res.setHeader('Content-Type', 'application/manifest+json');
    if (filePath.includes('service-worker'))
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
}));

const limiter      = rateLimit({ windowMs: 15*60*1000, max: 300, standardHeaders: true, legacyHeaders: false,
  message: { erro: 'Muitas requisicoes. Aguarde alguns minutos.' }
});
const loginLimiter = rateLimit({ windowMs: 10*60*1000, max: 10,
  message: { erro: 'Muitas tentativas de login. Aguarde 10 minutos.' }
});
const iaLimiter      = rateLimit({ windowMs: 60*1000, max: 20,
  message: { erro: 'Limite de analise IA atingido. Aguarde 1 minuto.' }
});
const iaAdminLimiter = rateLimit({ windowMs: 60*1000, max: 300,
  message: { erro: 'Limite admin IA atingido.' }
});
app.use('/api', limiter);

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════
const getIP   = req => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
const isObjId = id  => mongoose.Types.ObjectId.isValid(id) && String(new mongoose.Types.ObjectId(id)) === String(id);
const normTel = t   => String(t||'').replace(/\D/g,'');
const horaAtual = () => new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
const gerarSenha = (n=10) => crypto.randomBytes(16).toString('base64').replace(/[^a-zA-Z0-9]/g,'').substring(0,n);

async function registrarLog(tipo, descricao, usuario='sistema', ip='') {
  try { await Log.create({ tipo, descricao, usuario, ip }); } catch(e) {}
}

async function telNaBlacklist(telefone) {
  return Blacklist.findOne({ telefone: normTel(telefone), ativo: true, dataVencimento: { $gt: new Date() } });
}

async function enviarEmail(para, assunto, html) {
  if (!RESEND_KEY || !para) { console.log(`[EMAIL SIM] Para:${para} | ${assunto}`); return false; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: EMAIL_FROM, to: [para], subject: assunto, html })
    });
    return r.ok;
  } catch(e) { console.error('Email error:', e.message); return false; }
}

// ═══════════════════════════════════════════════════════════
// AUTH MIDDLEWARES
// ═══════════════════════════════════════════════════════════
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ erro: 'Sessão expirada — faça login novamente' }); }
}

function adminAuth(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin') return res.status(403).json({ erro: 'Acesso negado — requer admin' });
    next();
  });
}

// ═══════════════════════════════════════════════════════════
// SEED INICIAL (roda quando banco está vazio)
// ═══════════════════════════════════════════════════════════
async function seedInicial() {
  try {
    // Admin padrão
    if (await Admin.countDocuments() === 0) {
      await Admin.create({
        usuario: 'admin', nome: 'Administrador Principal', nivel: 'super', email: '',
        senhaHash: await bcrypt.hash('Deusdaminhavida4321', 12)
      });
      console.log('✅ Admin criado: admin / Deusdaminhavida4321');
    }

    // Configs padrão
    const configs = [
      { chave:'cidade',       valor:'Piatã' },
      { chave:'estado',       valor:'BA' },
      { chave:'whatsapp',     valor:'5575999999999' },
      { chave:'precos_planos', valor:{ basico:39.90, pro:69.90, premium:119.90 } }
    ];
    for (const c of configs) {
      await Config.findOneAndUpdate({ chave: c.chave }, { $setOnInsert: { valor: c.valor } }, { upsert: true });
    }

    // Produtos — se banco tiver menos que o seed, reseta com seed completo
    const totalProdutos = await Produto.countDocuments();
    if (totalProdutos < PRODUTOS_SEED.length) {
      await Produto.deleteMany({});
      await Produto.insertMany(PRODUTOS_SEED, { ordered: false }).catch(()=>{});
      const totalNovo = await Produto.countDocuments({ ativo: true });
      console.log(`✅ Catálogo resetado: ${totalNovo} produtos do seed`);
    } else {
      const totalAtivos = await Produto.countDocuments({ ativo: true });
      console.log(`✅ Catálogo OK: ${totalAtivos} produtos ativos no banco`);
    }

    // Mercados demo — APENAS se banco completamente vazio E variável de ambiente SEED_DEMO=true
    // NUNCA inserir automaticamente em produção — protege dados reais
    const totalMercados = await Mercado.countDocuments();
    if (totalMercados === 0 && process.env.SEED_DEMO === 'true') {
      await Mercado.insertMany([
        { nome:'Mercado Exemplo 1', icone:'🏪', endereco:'Rua Principal, 1', bairro:'Centro', lat:null, lng:null },
        { nome:'Mercado Exemplo 2', icone:'🛒', endereco:'Av. Central, 10',  bairro:'Centro', lat:null, lng:null },
      ]);
      console.log('[Seed] Mercados demo criados (SEED_DEMO=true)');
    } else {
      console.log('[Seed] Mercados no banco: ' + totalMercados + ' — seed demo ignorado');
    }

    // Limpar blacklist vencida inicial
    await Blacklist.updateMany({ dataVencimento: { $lte: new Date() }, ativo: true }, { ativo: false });

  } catch(e) { console.error('Erro seed:', e.message); }
}

// ═══════════════════════════════════════════════════════════
// CATÁLOGO — PRODUTOS SEED
// ═══════════════════════════════════════════════════════════
const PRODUTOS_SEED = [
  // FRUTAS
  {nome:'Banana Prata kg',emoji:'🍌',categoria:'Frutas'},
  {nome:'Banana Nanica kg',emoji:'🍌',categoria:'Frutas'},
  {nome:'Maçã Fuji kg',emoji:'🍎',categoria:'Frutas'},
  {nome:'Maçã Gala kg',emoji:'🍎',categoria:'Frutas'},
  {nome:'Laranja Lima kg',emoji:'🍊',categoria:'Frutas'},
  {nome:'Laranja Pera kg',emoji:'🍊',categoria:'Frutas'},
  {nome:'Limão Tahiti kg',emoji:'🍋',categoria:'Frutas'},
  {nome:'Abacaxi Pérola un',emoji:'🍍',categoria:'Frutas'},
  {nome:'Mamão Formosa kg',emoji:'🧡',categoria:'Frutas'},
  {nome:'Mamão Papaia kg',emoji:'🧡',categoria:'Frutas'},
  {nome:'Manga Tommy kg',emoji:'🥭',categoria:'Frutas'},
  {nome:'Manga Espada kg',emoji:'🥭',categoria:'Frutas'},
  {nome:'Uva Itália kg',emoji:'🍇',categoria:'Frutas'},
  {nome:'Melancia kg',emoji:'🍉',categoria:'Frutas'},
  {nome:'Morango cx 300g',emoji:'🍓',categoria:'Frutas'},
  {nome:'Goiaba kg',emoji:'💚',categoria:'Frutas'},
  {nome:'Maracujá kg',emoji:'🟣',categoria:'Frutas'},
  {nome:'Abacate kg',emoji:'🥑',categoria:'Frutas'},
  {nome:'Coco Verde un',emoji:'🥥',categoria:'Frutas'},
  {nome:'Tangerina Ponkan kg',emoji:'🍊',categoria:'Frutas'},
  {nome:'Acerola kg',emoji:'🔴',categoria:'Frutas'},
  {nome:'Kiwi kg',emoji:'🥝',categoria:'Frutas'},
  {nome:'Pera Williams kg',emoji:'🍐',categoria:'Frutas'},
  {nome:'Melão Amarelo kg',emoji:'🍈',categoria:'Frutas'},
  {nome:'Uva Rubi kg',emoji:'🍇',categoria:'Frutas'},
  // VERDURAS
  {nome:'Alface Americana un',emoji:'🥬',categoria:'Verduras'},
  {nome:'Alface Crespa un',emoji:'🥬',categoria:'Verduras'},
  {nome:'Rúcula maço',emoji:'🌿',categoria:'Verduras'},
  {nome:'Couve maço',emoji:'🥬',categoria:'Verduras'},
  {nome:'Repolho Verde un',emoji:'🥬',categoria:'Verduras'},
  {nome:'Agrião maço',emoji:'🌿',categoria:'Verduras'},
  {nome:'Chicória maço',emoji:'🌿',categoria:'Verduras'},
  {nome:'Espinafre maço',emoji:'🥬',categoria:'Verduras'},
  {nome:'Repolho Roxo un',emoji:'🥬',categoria:'Verduras'},
  // LEGUMES
  {nome:'Tomate Salada kg',emoji:'🍅',categoria:'Legumes'},
  {nome:'Tomate Cereja cx',emoji:'🍅',categoria:'Legumes'},
  {nome:'Cebola Branca kg',emoji:'🧅',categoria:'Legumes'},
  {nome:'Cebola Roxa kg',emoji:'🧅',categoria:'Legumes'},
  {nome:'Alho Nacional kg',emoji:'🧄',categoria:'Legumes'},
  {nome:'Batata Inglesa kg',emoji:'🥔',categoria:'Legumes'},
  {nome:'Batata Doce kg',emoji:'🍠',categoria:'Legumes'},
  {nome:'Cenoura kg',emoji:'🥕',categoria:'Legumes'},
  {nome:'Beterraba kg',emoji:'🟣',categoria:'Legumes'},
  {nome:'Abobrinha kg',emoji:'🥒',categoria:'Legumes'},
  {nome:'Chuchu kg',emoji:'🟢',categoria:'Legumes'},
  {nome:'Pepino kg',emoji:'🥒',categoria:'Legumes'},
  {nome:'Pimentão Verde kg',emoji:'🫑',categoria:'Legumes'},
  {nome:'Pimentão Vermelho kg',emoji:'🫑',categoria:'Legumes'},
  {nome:'Milho Verde un',emoji:'🌽',categoria:'Legumes'},
  {nome:'Quiabo kg',emoji:'🟢',categoria:'Legumes'},
  {nome:'Berinjela kg',emoji:'🟣',categoria:'Legumes'},
  {nome:'Pimentão Amarelo kg',emoji:'🫑',categoria:'Legumes'},
  // MERCEARIA
  {nome:'Arroz Camil Branco 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Camil Branco 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Tio João Branco 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Prato Fino 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Namorado Branco 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Blue Ville 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Integral Camil 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Parboilizado Camil 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Feijão Carioca Camil 1kg',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Feijão Carioca Kicaldo 1kg',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Feijão Preto Camil 1kg',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Feijão Verde Carioca 1kg',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Lentilha 500g',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Grão de Bico 500g',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Açúcar União Refinado 1kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Açúcar União Cristal 1kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Açúcar Caravelas 1kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Açúcar União 5kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Açúcar Cristal Caravelas 5kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Sal Refinado Cisne 1kg',emoji:'🧂',categoria:'Mercearia'},
  {nome:'Sal Grosso 1kg',emoji:'🧂',categoria:'Mercearia'},
  {nome:'Café Pilão Torrado 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Pilão Torrado 250g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Melitta Extra Forte 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café 3 Corações 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Pelé 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Caboclo 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Nescafé Solúvel 100g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Piatã Torrado Local 250g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Café Rigno 500g',emoji:'☕',categoria:'Mercearia'},
  {nome:'Farinha de Trigo Dona Benta 1kg',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Farinha de Trigo Anaconda 1kg',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Farinha de Mandioca Crua 1kg',emoji:'🟤',categoria:'Mercearia'},
  {nome:'Farinha de Mandioca Torrada 1kg',emoji:'🟤',categoria:'Mercearia'},
  {nome:'Fubá Mimoso Quaker 1kg',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Amido de Milho Maisena 400g',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Macarrão Espaguete Renata 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Macarrão Parafuso Nissin 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Macarrão Cotovelo Adria 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Macarrão Instantâneo Miojo 85g',emoji:'🍜',categoria:'Mercearia'},
  {nome:'Macarrão Instantâneo Nissin 85g',emoji:'🍜',categoria:'Mercearia'},
  {nome:'Óleo de Soja Liza 900ml',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Óleo de Soja Soya 900ml',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Azeite Gallo Extra Virgem 500ml',emoji:'🫒',categoria:'Mercearia'},
  {nome:'Azeite Carbonell 500ml',emoji:'🫒',categoria:'Mercearia'},
  {nome:'Molho de Tomate Pomarola 520g',emoji:'🍅',categoria:'Mercearia'},
  {nome:'Molho de Tomate Quero 520g',emoji:'🍅',categoria:'Mercearia'},
  {nome:'Extrato de Tomate Elefante 190g',emoji:'🍅',categoria:'Mercearia'},
  {nome:'Sardinha Coqueiro 125g',emoji:'🐟',categoria:'Mercearia'},
  {nome:'Atum Gomes da Costa 170g',emoji:'🐠',categoria:'Mercearia'},
  {nome:'Milho Verde Quero 200g',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Ervilha Quero 200g',emoji:'🟢',categoria:'Mercearia'},
  {nome:'Molho de Tomate Heinz 340g',emoji:'🍅',categoria:'Mercearia'},
  {nome:'Maionese Hellmanns 500g',emoji:'🟡',categoria:'Mercearia'},
  {nome:'Vinagre Castelo 750ml',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Shoyu Kikkoman 150ml',emoji:'🍶',categoria:'Mercearia'},
  {nome:'Leite em Pó Ninho Integral 400g',emoji:'🥛',categoria:'Mercearia'},
  {nome:'Leite em Pó Itambé 400g',emoji:'🥛',categoria:'Mercearia'},
  {nome:'Leite Condensado Moça 395g',emoji:'🥛',categoria:'Mercearia'},
  {nome:'Leite Condensado Itambé 395g',emoji:'🥛',categoria:'Mercearia'},
  {nome:'Creme de Leite Nestlé 200g',emoji:'🥛',categoria:'Mercearia'},
  {nome:'Achocolatado Nescau 400g',emoji:'🍫',categoria:'Mercearia'},
  {nome:'Achocolatado Toddy 400g',emoji:'🍫',categoria:'Mercearia'},
  {nome:'Biscoito Recheado Oreo 120g',emoji:'🍪',categoria:'Mercearia'},
  {nome:'Biscoito Cream Cracker Triunfo 200g',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Aveia Quaker Flocos 500g',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Fermento Royal 200g',emoji:'🧁',categoria:'Mercearia'},
  {nome:'Arroz Tio João Branco 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Prato Fino 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Urbano Branco 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Integral Tio João 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Integral Namorado 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Integral Prato Fino 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Integral Urbano 1kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Arroz Parboilizado Tio João 5kg',emoji:'🍚',categoria:'Mercearia'},
  {nome:'Feijão Carioca Fazendeiro 1kg',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Feijão Carioca Mistura 500g',emoji:'🫘',categoria:'Mercearia'},
  {nome:'Açúcar Demerara 1kg',emoji:'🍬',categoria:'Mercearia'},
  {nome:'Farinha de Trigo Sol 1kg',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Farinha de Rosca 500g',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Fubá Yoki 1kg',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Macarrão Espaguete Adria 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Macarrão Fusilli Barilla 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Macarrão Penne Barilla 500g',emoji:'🍝',categoria:'Mercearia'},
  {nome:'Azeite Andorinha 500ml',emoji:'🫒',categoria:'Mercearia'},
  {nome:'Óleo de Girassol Liza 900ml',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Óleo de Soja Cocamar 900ml',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Catchup Heinz 397g',emoji:'🍅',categoria:'Mercearia'},
  {nome:'Granola Jasmine 500g',emoji:'🌾',categoria:'Mercearia'},
  {nome:'Canjica Amarela 500g',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Gelatina Royal 250g',emoji:'🟥',categoria:'Mercearia'},
  {nome:'Cereal Sucrilhos Kelloggs 300g',emoji:'🌽',categoria:'Mercearia'},
  {nome:'Biscoito Cream Cracker Adria 200g',emoji:'🫙',categoria:'Mercearia'},
  {nome:'Biscoito Maisena Nestlé 200g',emoji:'🍪',categoria:'Mercearia'},
  {nome:'Biscoito Recheado Negresco 120g',emoji:'🍪',categoria:'Mercearia'},
  {nome:'Biscoito Recheado Trakinas 132g',emoji:'🍪',categoria:'Mercearia'},
  {nome:'Bolacha Maizena Isabela 200g',emoji:'🍪',categoria:'Mercearia'},
  {nome:'Achocolatado Nescau 2kg',emoji:'🍫',categoria:'Mercearia'},
  // AÇOUGUE
  {nome:'Patinho Bovino kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Alcatra kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Picanha kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Fraldinha kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Acém kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Carne Moída Patinho kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Carne Moída Acém kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Frango Inteiro Congelado kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Peito de Frango kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Coxa e Sobrecoxa kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Filé de Frango kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Linguiça Perdigão Calabresa kg',emoji:'🌭',categoria:'Açougue'},
  {nome:'Linguiça Seara Toscana kg',emoji:'🌭',categoria:'Açougue'},
  {nome:'Costela Bovina kg',emoji:'🦴',categoria:'Açougue'},
  {nome:'Costela Suína kg',emoji:'🦴',categoria:'Açougue'},
  {nome:'Bacon Fatiado Sadia kg',emoji:'🥓',categoria:'Açougue'},
  {nome:'Tilápia Filé kg',emoji:'🐟',categoria:'Açougue'},
  {nome:'Camarão kg',emoji:'🦐',categoria:'Açougue'},
  {nome:'Carne de Sol kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Charque Bovino 500g',emoji:'🥩',categoria:'Açougue'},
  {nome:'Salsicha Perdigão 500g',emoji:'🌭',categoria:'Açougue'},
  {nome:'Salsicha Sadia 500g',emoji:'🌭',categoria:'Açougue'},
  {nome:'Paleta Bovina kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Asa de Frango kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Frango a Passarinho kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Fígado Bovino kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Moela de Frango kg',emoji:'🍗',categoria:'Açougue'},
  {nome:'Músculo kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Lombo Suíno kg',emoji:'🥩',categoria:'Açougue'},
  {nome:'Linguiça de Frango kg',emoji:'🌭',categoria:'Açougue'},
  {nome:'Presunto de Frango Sadia kg',emoji:'🍖',categoria:'Açougue'},
  {nome:'Hambúrguer Perdigão 672g 12un',emoji:'🍔',categoria:'Açougue'},
  // LATICÍNIOS
  {nome:'Leite Integral Piracanjuba 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite Integral Itambé 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite Integral Betânia 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite Desnatado Piracanjuba 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite Integral Parmalat 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Queijo Mussarela Fatiado kg',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Queijo Prato Fatiado kg',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Queijo Minas Frescal kg',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Queijo Coalho kg',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Presunto Sadia Fatiado kg',emoji:'🍖',categoria:'Laticínios'},
  {nome:'Mortadela Perdigão kg',emoji:'🍖',categoria:'Laticínios'},
  {nome:'Requeijão Catupiry 200g',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Iogurte Integral Danone 170g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Manteiga com Sal Aviação 200g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Manteiga sem Sal 200g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Margarina Qualy 500g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Cream Cheese Philadelphia 150g',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Ovos Brancos dúzia',emoji:'🥚',categoria:'Laticínios'},
  {nome:'Leite Integral Tirol 1L',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite Condensado Campo Belo 395g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Leite em Pó Ninho Forti+ 400g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Iogurte Natural Integral 170g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Iogurte Grego Danone 90g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Iogurte Yopro Proteico 160g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Manteiga com Sal Itambé 200g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Manteiga Aviação sem Sal 200g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Manteiga Vigor com Sal 200g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Margarina Becel 500g',emoji:'🧈',categoria:'Laticínios'},
  {nome:'Requeijão Nestlé 200g',emoji:'🧀',categoria:'Laticínios'},
  {nome:'Creme de Leite Piracanjuba 200g',emoji:'🥛',categoria:'Laticínios'},
  {nome:'Apresentado Perdigão kg',emoji:'🍖',categoria:'Laticínios'},
  // BEBIDAS
  {nome:'Coca-Cola 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Coca-Cola Lata 350ml',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Coca-Cola Zero 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Guaraná Antarctica 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Guaraná Antarctica Lata 350ml',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Fanta Laranja 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Fanta Uva 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Pepsi 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Sprite 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Água Mineral Crystal 1,5L',emoji:'💧',categoria:'Bebidas'},
  {nome:'Água Mineral Indaiá 1,5L',emoji:'💧',categoria:'Bebidas'},
  {nome:'Suco Del Valle Uva 1L',emoji:'🧃',categoria:'Bebidas'},
  {nome:'Suco Tropicana Laranja 1L',emoji:'🧃',categoria:'Bebidas'},
  {nome:'Suco Maguary Maracujá 1L',emoji:'🧃',categoria:'Bebidas'},
  {nome:'Energético Red Bull 250ml',emoji:'⚡',categoria:'Bebidas'},
  {nome:'Energético Monster 473ml',emoji:'⚡',categoria:'Bebidas'},
  {nome:'Cerveja Skol Lata 350ml',emoji:'🍺',categoria:'Bebidas'},
  {nome:'Cerveja Brahma Lata 350ml',emoji:'🍺',categoria:'Bebidas'},
  {nome:'Cerveja Itaipava Lata 350ml',emoji:'🍺',categoria:'Bebidas'},
  {nome:'Cerveja Heineken Long Neck 330ml',emoji:'🍺',categoria:'Bebidas'},
  {nome:'Cerveja Budweiser Lata 350ml',emoji:'🍺',categoria:'Bebidas'},
  {nome:'Guaraná Jesus 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Kuat 2L',emoji:'🥤',categoria:'Bebidas'},
  {nome:'Suco Ades Laranja 1L',emoji:'🧃',categoria:'Bebidas'},
  {nome:'Limonada Pronta 500ml',emoji:'🍋',categoria:'Bebidas'},
  {nome:'Água com Gás Lindoya 1L',emoji:'💧',categoria:'Bebidas'},
  {nome:'Água de Coco 1L',emoji:'🥥',categoria:'Bebidas'},
  {nome:'Vinho Tinto Seco 750ml',emoji:'🍷',categoria:'Bebidas'},
  // DOCES
  {nome:'Chocolate Lacta ao Leite 80g',emoji:'🍫',categoria:'Doces'},
  {nome:'Chocolate Nestlé Kit Kat 42g',emoji:'🍫',categoria:'Doces'},
  {nome:'Chocolate Bis Lacta 100g',emoji:'🍫',categoria:'Doces'},
  {nome:'Paçoca Rolha Santa Helena 50g',emoji:'🟤',categoria:'Doces'},
  {nome:'Doce de Leite Itambé 400g',emoji:'🍯',categoria:'Doces'},
  {nome:'Goiabada Predilecta 300g',emoji:'🟥',categoria:'Doces'},
  {nome:'Bombom Sonho de Valsa 200g',emoji:'🍬',categoria:'Doces'},
  {nome:'Marshmallow Fini 250g',emoji:'🤍',categoria:'Doces'},
  {nome:'Bala Fini 100g',emoji:'🍬',categoria:'Doces'},
  {nome:'Chiclete Trident 8un',emoji:'🟢',categoria:'Doces'},
  {nome:'Pirulito Chupa Chups un',emoji:'🍭',categoria:'Doces'},
  {nome:'Pé de Moleque Barra 100g',emoji:'🟤',categoria:'Doces'},
  {nome:'Cocada Branca 200g',emoji:'⚪',categoria:'Doces'},
  {nome:'Chocolate Garoto ao Leite 80g',emoji:'🍫',categoria:'Doces'},
  // LIMPEZA
  {nome:'Sabão em Pó OMO 1kg',emoji:'🧺',categoria:'Limpeza'},
  {nome:'Sabão em Pó Ariel 1kg',emoji:'🧺',categoria:'Limpeza'},
  {nome:'Sabão em Pó Ypê 1kg',emoji:'🧺',categoria:'Limpeza'},
  {nome:'Sabão Líquido OMO 1L',emoji:'🫧',categoria:'Limpeza'},
  {nome:'Amaciante Comfort 1L',emoji:'🌸',categoria:'Limpeza'},
  {nome:'Amaciante Downy 1L',emoji:'🌸',categoria:'Limpeza'},
  {nome:'Detergente Ypê Neutro 500ml',emoji:'🫧',categoria:'Limpeza'},
  {nome:'Detergente Limpol 500ml',emoji:'🫧',categoria:'Limpeza'},
  {nome:'Água Sanitária Qboa 1L',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Desinfetante Pinho Sol 1L',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Esponja Bombril Limpeza 3 un',emoji:'🟨',categoria:'Limpeza'},
  {nome:'Multiuso Mr. Músculo 500ml',emoji:'🧹',categoria:'Limpeza'},
  {nome:'Álcool Gel 70% 500ml',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Álcool Líquido 70% 1L',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Sabão em Pó Brilhante 1kg',emoji:'🧺',categoria:'Limpeza'},
  {nome:'Sabão de Coco em Pedra 200g',emoji:'🧼',categoria:'Limpeza'},
  {nome:'Lava Roupas Omo Líquido 2L',emoji:'🫧',categoria:'Limpeza'},
  {nome:'Tira Manchas Vanish 450g',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Amaciante Fofo 2L',emoji:'🌸',categoria:'Limpeza'},
  {nome:'Detergente Minuano 500ml',emoji:'🫧',categoria:'Limpeza'},
  {nome:'Brilhante Desincrustante 500ml',emoji:'✨',categoria:'Limpeza'},
  {nome:'Desinfetante Flora 1L',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Limpa Vidros Windex 500ml',emoji:'🔵',categoria:'Limpeza'},
  {nome:'Inseticida Raid Aerosol 300ml',emoji:'🟢',categoria:'Limpeza'},
  {nome:'Repelente Off 200ml',emoji:'🟢',categoria:'Limpeza'},
  {nome:'Desentupidor Liquido Destampou 500ml',emoji:'🪣',categoria:'Limpeza'},
  {nome:'Palha de Aço Bombril 8 un',emoji:'🟡',categoria:'Limpeza'},
  {nome:'Rodo 60cm un',emoji:'🧹',categoria:'Limpeza'},
  {nome:'Vassoura Dupla Ação un',emoji:'🧹',categoria:'Limpeza'},
  {nome:'Pano de Prato Kala 3un',emoji:'🤍',categoria:'Limpeza'},
  {nome:'Água Sanitária Ype 1L',emoji:'🧴',categoria:'Limpeza'},
  {nome:'Álcool Líquido Ingleza 70% 1L',emoji:'🧴',categoria:'Limpeza'},
  // HIGIENE
  {nome:'Sabonete Dove Hidratante 90g',emoji:'🧼',categoria:'Higiene'},
  {nome:'Sabonete Lux 90g',emoji:'🧼',categoria:'Higiene'},
  {nome:'Sabonete Palmolive 90g',emoji:'🧼',categoria:'Higiene'},
  {nome:'Shampoo Seda 325ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Shampoo Pantene 400ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Condicionador Seda 325ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Pasta Colgate Tripla Ação 90g',emoji:'🦷',categoria:'Higiene'},
  {nome:'Pasta Oral-B 70g',emoji:'🦷',categoria:'Higiene'},
  {nome:'Pasta Sorriso 90g',emoji:'🦷',categoria:'Higiene'},
  {nome:'Desodorante Rexona Roll-On 50ml',emoji:'🌸',categoria:'Higiene'},
  {nome:'Desodorante Dove Spray 150ml',emoji:'🌸',categoria:'Higiene'},
  {nome:'Papel Higiênico Neve 4 rolos',emoji:'🧻',categoria:'Higiene'},
  {nome:'Papel Higiênico Personal 4 rolos',emoji:'🧻',categoria:'Higiene'},
  {nome:'Papel Higiênico Snob 4 rolos',emoji:'🧻',categoria:'Higiene'},
  {nome:'Papel Higiênico Paloma 4 rolos',emoji:'🧻',categoria:'Higiene'},
  {nome:'Papel Higiênico Paloma 12 rolos',emoji:'🧻',categoria:'Higiene'},
  {nome:'Absorvente Always com Abas 8un',emoji:'💜',categoria:'Higiene'},
  {nome:'Absorvente Intimus 8un',emoji:'💜',categoria:'Higiene'},
  {nome:'Fralda Pampers P 28un',emoji:'👶',categoria:'Higiene'},
  {nome:'Fralda Pampers M 26un',emoji:'👶',categoria:'Higiene'},
  {nome:'Fralda Huggies M 24un',emoji:'👶',categoria:'Higiene'},
  {nome:'Creme Nívea Hidratante 200ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Shampoo Head Shoulders 200ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Shampoo Seda Ceramidas 325ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Condicionador Pantene 400ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Máscara Capilar Elseve 300ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Creme para Cabelo Salon Line 300g',emoji:'🧴',categoria:'Higiene'},
  {nome:'Creme para Pentear Novex 300g',emoji:'🧴',categoria:'Higiene'},
  {nome:'Gel Capilar Fixador Taft 250ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Óleo Capilar Wella 30ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Escova Dental Colgate 1un',emoji:'🦷',categoria:'Higiene'},
  {nome:'Desodorante Nívea Roll-On 50ml',emoji:'🌸',categoria:'Higiene'},
  {nome:'Creme Facial Nivea Antissinais 50ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Hidratante Corporal Dove 400ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Hidratante Corporal Nivea 400ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Cera Squeeze Johnson 200ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Algodão Johnson 50g',emoji:'⚪',categoria:'Higiene'},
  {nome:'Cotonete Johnson 75un',emoji:'⚪',categoria:'Higiene'},
  {nome:'Lâmina Gillette Prestobarba 2un',emoji:'🪒',categoria:'Higiene'},
  {nome:'Protetor Solar Neutrogena FPS70 200ml',emoji:'🌞',categoria:'Higiene'},
  {nome:'Protetor Solar Sundown FPS50 200ml',emoji:'🌞',categoria:'Higiene'},
  {nome:'Protetor Solar Episol FPS50 120ml',emoji:'🌞',categoria:'Higiene'},
  {nome:'Demaquilante Bifásico Océane 120ml',emoji:'🧴',categoria:'Higiene'},
  {nome:'Demaquilante Nivea 200ml',emoji:'🧴',categoria:'Higiene'},
  // PADARIA
  {nome:'Pão Francês kg',emoji:'🥖',categoria:'Padaria'},
  {nome:'Pão Francês un',emoji:'🥖',categoria:'Padaria'},
  {nome:'Pão de Forma Wickbold 500g',emoji:'🍞',categoria:'Padaria'},
  {nome:'Pão de Forma Nutrella 500g',emoji:'🍞',categoria:'Padaria'},
  {nome:'Pão Hot Dog 8un',emoji:'🌭',categoria:'Padaria'},
  {nome:'Pão Hot Dog un',emoji:'🌭',categoria:'Padaria'},
  {nome:'Pão Hambúrguer 8un',emoji:'🍔',categoria:'Padaria'},
  {nome:'Pão Hambúrguer un',emoji:'🍔',categoria:'Padaria'},
  {nome:'Bolo de Milho un',emoji:'🎂',categoria:'Padaria'},
  {nome:'Pão Integral Seven Boys 500g',emoji:'🍞',categoria:'Padaria'},
  {nome:'Sonho recheado un',emoji:'🥐',categoria:'Padaria'},
  {nome:'Coxinha un',emoji:'🍗',categoria:'Padaria'},
  {nome:'Empada un',emoji:'🥧',categoria:'Padaria'},
  {nome:'Salgado Frito un',emoji:'🥟',categoria:'Padaria'},
  {nome:'Salgado Assado un',emoji:'🥐',categoria:'Padaria'},
  {nome:'Esfirra un',emoji:'🥙',categoria:'Padaria'},
  {nome:'Pastel un',emoji:'🥟',categoria:'Padaria'},
  // CONGELADOS
  {nome:'Pizza Sadia Mussarela 460g',emoji:'🍕',categoria:'Congelados'},
  {nome:'Hambúrguer Sadia 672g 12un',emoji:'🍔',categoria:'Congelados'},
  {nome:'Nuggets de Frango Sadia 300g',emoji:'🍗',categoria:'Congelados'},
  {nome:'Lasanha Bolonhesa Sadia 600g',emoji:'🫕',categoria:'Congelados'},
  {nome:'Batata Frita McCain 400g',emoji:'🍟',categoria:'Congelados'},
  {nome:'Açaí Polpa Nativo 1kg',emoji:'💜',categoria:'Congelados'},
  {nome:'Sorvete Kibon Pote Chocolate 1,5L',emoji:'🍦',categoria:'Congelados'},
  {nome:'Pizza Seara Calabresa 460g',emoji:'🍕',categoria:'Congelados'},
  {nome:'Lasanha Frango Sadia 600g',emoji:'🫕',categoria:'Congelados'},
  {nome:'Nuggets de Frango Seara 300g',emoji:'🍗',categoria:'Congelados'},
  {nome:'Sorvete Kibon Pote Morango 1,5L',emoji:'🍦',categoria:'Congelados'},
  {nome:'Sorvete Nestlé Pote Napolitano 1,5L',emoji:'🍦',categoria:'Congelados'},
  {nome:'Picolé Kibon Chocolate un',emoji:'🍦',categoria:'Congelados'},
  {nome:'Picolé Kibon Limão un',emoji:'🍦',categoria:'Congelados'},
  {nome:'Picolé Magnum un',emoji:'🍦',categoria:'Congelados'},
  {nome:'Polpa Maracujá 1kg',emoji:'🟣',categoria:'Congelados'},
  {nome:'Polpa Morango 1kg',emoji:'🍓',categoria:'Congelados'},
  {nome:'Açaí Polpa Sambazon 400g',emoji:'💜',categoria:'Congelados'},
  // UTILIDADES
  {nome:'Papel Alumínio Wyda 30cm 30m',emoji:'🪙',categoria:'Utilidades'},
  {nome:'Saco de Lixo 100L 10un',emoji:'🗑️',categoria:'Utilidades'},
  {nome:'Saco de Lixo 60L 10un',emoji:'🗑️',categoria:'Utilidades'},
  {nome:'Guardanapo de Papel 50un',emoji:'🤍',categoria:'Utilidades'},
  {nome:'Copo Descartável 200ml 50un',emoji:'🥤',categoria:'Utilidades'},
  {nome:'Fósforo 40 palitos',emoji:'🔥',categoria:'Utilidades'},
  {nome:'Pilha AA Duracell 2un',emoji:'🔋',categoria:'Utilidades'},
  {nome:'Acetona Kolene 100ml',emoji:'💅',categoria:'Utilidades'},
  {nome:'Pilha AA Philips 4un',emoji:'🔋',categoria:'Utilidades'},
  {nome:'Prato Descartável 15cm 10un',emoji:'🍽️',categoria:'Utilidades'},
  {nome:'Papel Manteiga 25cm',emoji:'🟡',categoria:'Utilidades'},
  {nome:'Sal Marinho Integral 500g',emoji:'🧂',categoria:'Utilidades'},
  // COSMÉTICOS
  {nome:'Base Maybelline Fit Me 30ml',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Batom Avon un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Batom Maybelline un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Batom Natura un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Blush Avon un',emoji:'🌸',categoria:'Cosméticos'},
  {nome:'Colônia Avon un',emoji:'💐',categoria:'Cosméticos'},
  {nome:'Corretivo Maybelline Instant Age un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Delineador Dailus un',emoji:'✏️',categoria:'Cosméticos'},
  {nome:'Esmalte Risqué un',emoji:'💅',categoria:'Cosméticos'},
  {nome:'Esmalte Colorama un',emoji:'💅',categoria:'Cosméticos'},
  {nome:'Esmalte OPI un',emoji:'💅',categoria:'Cosméticos'},
  {nome:'Espelho de Bolso un',emoji:'🪞',categoria:'Cosméticos'},
  {nome:'Iluminador Dailus un',emoji:'✨',categoria:'Cosméticos'},
  {nome:'Paleta de Sombras Ruby Rose un',emoji:'🎨',categoria:'Cosméticos'},
  {nome:'Perfume Feminino Natura una 75ml',emoji:'💐',categoria:'Cosméticos'},
  {nome:'Perfume Masculino Natura Humor 75ml',emoji:'💐',categoria:'Cosméticos'},
  {nome:'Pinça de Sobrancelha un',emoji:'🔧',categoria:'Cosméticos'},
  {nome:'Pó Compacto Avon un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Pó Compacto Maybelline un',emoji:'💄',categoria:'Cosméticos'},
  {nome:'Rímel Avon Super Extend un',emoji:'👁️',categoria:'Cosméticos'},
  {nome:'Rímel Maybelline Lash Sensational un',emoji:'👁️',categoria:'Cosméticos'},
  {nome:'Sombra Jasmyne un',emoji:'🎨',categoria:'Cosméticos'},
  {nome:'Tintura de Cabelo Garnier un',emoji:'💇',categoria:'Cosméticos'},
  {nome:'Tintura de Cabelo Igora un',emoji:'💇',categoria:'Cosméticos'},
];;

// ═══════════════════════════════════════════════════════════
// SSE — ADMINS ONLINE
// ═══════════════════════════════════════════════════════════
const adminsOnline = new Map();
function notificarAdmins(evento, dados) {
  for (const [, a] of adminsOnline) {
    if (a.res && !a.res.writableEnded)
      a.res.write(`event: ${evento}\ndata: ${JSON.stringify(dados)}\n\n`);
  }
}

// ═══════════════════════════════════════════════════════════
// ██ ROTAS ██
// ═══════════════════════════════════════════════════════════

// ── HEALTH ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status:'ok', app:'PreçoCerto', versao:'8.0.0', db: mongoose.connection.readyState===1 ? 'conectado':'desconectado', ts: new Date().toISOString() });
});

// ── IA PROXY (Gemini) ────────────────────────────────────
app.post('/api/ia/analisar', iaLimiter, async (req, res) => {
  if (!GEMINI_KEY) return res.status(503).json({ erro:'IA não configurada. Adicione GEMINI_API_KEY nas variáveis de ambiente do Render.' });
  const { imageBase64, mediaType, prompt } = req.body;
  if (!prompt) return res.status(400).json({ erro:'prompt obrigatório' });
  try {
    // ── Verifica cache de imagem (evita chamar IA para a mesma foto) ──
    if (imageBase64) {
      const hash = hashBase64Leve(imageBase64);
      const cached = await CacheIA.findOne({ hashImagem: hash }).catch(()=>null);
      if (cached && cached.resultado) {
        await CacheIA.updateOne({ _id: cached._id }, { $inc: { usos: 1 }, $set: { expiraEm: new Date(Date.now()+90*24*60*60*1000) } }).catch(()=>{}); // Renova TTL 90 dias a cada uso
        const textoCache = typeof cached.resultado === 'string'
          ? cached.resultado
          : JSON.stringify(cached.resultado);
        console.log(`[CacheIA] Hit! hash=${hash} usos=${cached.usos+1}`);
        return res.json({ texto: textoCache, cache: true });
      }
    }

    const parts = [];
    if (imageBase64) parts.push({ inlineData:{ mimeType: mediaType||'image/jpeg', data: imageBase64 } });
    parts.push({ text: prompt });

    // Cadeia de fallback ampla: tenta vários modelos do Gemini
    // Ordena por estabilidade com imagens: 1.5-flash é o mais testado, 2.0-flash tem boa visão
    const modelos = ['gemini-2.5-flash-preview-04-17', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
    let ultimoErro = '';
    let quotaExceeded = false;
    for (const modelo of modelos) {
      try {
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${modelo}:generateContent?key=${GEMINI_KEY}`, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ contents:[{parts}], generationConfig:{ temperature:0.05, maxOutputTokens:8192 } })
        });
        const d = await r.json();
        if (d.error) {
          ultimoErro = d.error.message || JSON.stringify(d.error);
          // Se é erro de quota, marca e tenta próximo modelo
          if (ultimoErro.toLowerCase().includes('quota') || ultimoErro.toLowerCase().includes('rate') || r.status === 429) {
            quotaExceeded = true;
            console.warn(`[IA] Quota/rate limit no modelo ${modelo}, tentando próximo...`);
            continue;
          }
          // Outros erros: tenta próximo modelo
          console.warn(`[IA] Erro no modelo ${modelo}: ${ultimoErro}`);
          continue;
        }
        // Extrai texto — tenta múltiplos caminhos da resposta do Gemini
        let texto = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!texto) {
          // Tenta outras partes da resposta
          const parts2 = d.candidates?.[0]?.content?.parts || [];
          texto = parts2.map(p => p.text || '').join('').trim();
        }
        if (!texto) {
          const finishReason = d.candidates?.[0]?.finishReason;
          ultimoErro = `Resposta vazia do modelo ${modelo} (finishReason: ${finishReason || 'unknown'})`;
          console.warn('[IA]', ultimoErro, '| promptFeedback:', JSON.stringify(d.promptFeedback));
          continue;
        }
        // Log dos primeiros 400 chars da resposta para debug
        console.log('[IA]['+modelo+'] resposta ('+texto.length+' chars):', texto.slice(0,400));
        // Salva no cache se veio com imagem
        if (imageBase64) {
          const hash = hashBase64Leve(imageBase64);
          CacheIA.findOneAndUpdate(
            { hashImagem: hash },
            { hashImagem: hash, resultado: texto, usos: 1, expiraEm: new Date(Date.now()+90*24*60*60*1000) },
            { upsert: true }
          ).catch(()=>{});
        }
        return res.json({ texto, modelo });
      } catch(fetchErr) {
        ultimoErro = fetchErr.message || 'Erro de conexão';
        console.warn(`[IA] Fetch erro no modelo ${modelo}: ${ultimoErro}`);
        continue;
      }
    }
    // Mensagem amigável dependendo do tipo de erro
    if (quotaExceeded) {
      return res.status(429).json({ erro: 'Limite de uso da IA atingido. Tente novamente em alguns minutos. Dica: use a aba Manual para lançar preços enquanto isso.' });
    }
    return res.status(500).json({ erro: `Gemini retornou erro: ${ultimoErro}` });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CONFIG ───────────────────────────────────────────────

// ─── Rota multipart para iOS PWA (evita 'Load failed' com JSON grande) ────────
app.post('/api/ia/analisar-form', iaLimiter, async (req, res) => {
  if (!GEMINI_KEY) return res.status(503).json({ erro:'IA não configurada.' });
  try {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    await new Promise((ok, fail) => { req.on('end', ok); req.on('error', fail); });
    const body = Buffer.concat(chunks);
    const ct = req.headers['content-type'] || '';
    const bm = ct.match(/boundary=([^;]+)/);
    if (!bm) return res.status(400).json({ erro: 'boundary ausente' });
    const boundary = '--' + bm[1].trim();
    const parts2 = {};
    const bodyStr = body.toString('binary');
    const sections = bodyStr.split(boundary);
    for (const sec of sections) {
      const cdMatch = sec.match(/Content-Disposition:[^\r\n]*name="([^"]+)"/i);
      if (!cdMatch) continue;
      const fieldName = cdMatch[1];
      const sep = sec.indexOf('\r\n\r\n');
      if (sep === -1) continue;
      let val = sec.slice(sep + 4).replace(/\r\n--$/, '').replace(/\r\n$/, '');
      parts2[fieldName] = val;
    }
    const prompt = parts2['prompt'] || '';
    if (!prompt) return res.status(400).json({ erro: 'prompt obrigatorio' });
    let imageBase64 = null, mediaType = 'image/jpeg';
    if (parts2['image']) {
      imageBase64 = Buffer.from(parts2['image'], 'binary').toString('base64');
      mediaType = parts2['mediaType'] || 'image/jpeg';
    } else if (parts2['imageBase64']) {
      imageBase64 = parts2['imageBase64'];
      mediaType = parts2['mediaType'] || 'image/jpeg';
    }
    const iaParts = [];
    if (imageBase64) iaParts.push({ inlineData: { mimeType: mediaType, data: imageBase64 } });
    iaParts.push({ text: prompt });
    const modelos = ['gemini-2.5-flash-preview-04-17', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
    let ultimoErro = '';
    for (const modelo of modelos) {
      try {
        const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/'+modelo+':generateContent?key='+GEMINI_KEY, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ contents:[{parts:iaParts}], generationConfig:{ temperature:0.05, maxOutputTokens:8192 } })
        });
        const d = await r.json();
        if (d.error) { ultimoErro = d.error.message||''; continue; }
        const texto = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (texto) return res.json({ texto });
      } catch(e){ ultimoErro = e.message; }
    }
    return res.status(500).json({ erro: ultimoErro || 'Todos os modelos falharam' });
  } catch(e) {
    console.error('[IA form]', e.message);
    return res.status(500).json({ erro: e.message });
  }
});

app.post('/api/ia/analisar-admin', iaAdminLimiter, adminAuth, async (req, res) => {
  if (!GEMINI_KEY) return res.status(503).json({ erro:'IA não configurada. Adicione GEMINI_API_KEY nas variáveis de ambiente do Render.' });
  const { imageBase64, mediaType, prompt } = req.body;
  if (!prompt) return res.status(400).json({ erro:'prompt obrigatório' });
  try {
    // Cache também para admin (economiza cota)
    if (imageBase64) {
      const hash = hashBase64Leve(imageBase64);
      const cached = await CacheIA.findOne({ hashImagem: hash }).catch(()=>null);
      if (cached && cached.resultado) {
        await CacheIA.updateOne({ _id: cached._id }, { $inc: { usos: 1 }, $set: { expiraEm: new Date(Date.now()+90*24*60*60*1000) } }).catch(()=>{}); // Renova TTL 90 dias a cada uso
        const textoCache = typeof cached.resultado === 'string' ? cached.resultado : JSON.stringify(cached.resultado);
        return res.json({ texto: textoCache, cache: true });
      }
    }
    const parts = [];
    if (imageBase64) parts.push({ inlineData:{ mimeType: mediaType||'image/jpeg', data: imageBase64 } });
    parts.push({ text: prompt });

    // Cadeia de fallback ampla: tenta vários modelos do Gemini
    // Ordena por estabilidade com imagens: 1.5-flash é o mais testado, 2.0-flash tem boa visão
    const modelos = ['gemini-2.5-flash-preview-04-17', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
    let ultimoErro = '';
    let quotaExceeded = false;
    for (const modelo of modelos) {
      try {
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${modelo}:generateContent?key=${GEMINI_KEY}`, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ contents:[{parts}], generationConfig:{ temperature:0.05, maxOutputTokens:8192 } })
        });
        const d = await r.json();
        if (d.error) {
          ultimoErro = d.error.message || JSON.stringify(d.error);
          // Se é erro de quota, marca e tenta próximo modelo
          if (ultimoErro.toLowerCase().includes('quota') || ultimoErro.toLowerCase().includes('rate') || r.status === 429) {
            quotaExceeded = true;
            console.warn(`[IA] Quota/rate limit no modelo ${modelo}, tentando próximo...`);
            continue;
          }
          // Outros erros: tenta próximo modelo
          console.warn(`[IA] Erro no modelo ${modelo}: ${ultimoErro}`);
          continue;
        }
        // Extrai texto — tenta múltiplos caminhos da resposta do Gemini
        let texto = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!texto) {
          // Tenta outras partes da resposta
          const parts2 = d.candidates?.[0]?.content?.parts || [];
          texto = parts2.map(p => p.text || '').join('').trim();
        }
        if (!texto) {
          const finishReason = d.candidates?.[0]?.finishReason;
          ultimoErro = `Resposta vazia do modelo ${modelo} (finishReason: ${finishReason || 'unknown'})`;
          console.warn('[IA]', ultimoErro, '| promptFeedback:', JSON.stringify(d.promptFeedback));
          continue;
        }
        // Log dos primeiros 400 chars da resposta para debug
        console.log('[IA]['+modelo+'] resposta ('+texto.length+' chars):', texto.slice(0,400));
        return res.json({ texto, modelo });
      } catch(fetchErr) {
        ultimoErro = fetchErr.message || 'Erro de conexão';
        console.warn(`[IA] Fetch erro no modelo ${modelo}: ${ultimoErro}`);
        continue;
      }
    }
    // Mensagem amigável dependendo do tipo de erro
    if (quotaExceeded) {
      return res.status(429).json({ erro: 'Limite de uso da IA atingido. Tente novamente em alguns minutos. Dica: use a aba Manual para lançar preços enquanto isso.' });
    }
    return res.status(500).json({ erro: `Gemini retornou erro: ${ultimoErro}` });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CONFIG ───────────────────────────────────────────────
app.get('/api/config', async (req, res) => {
  try {
    const list = await Config.find();
    const obj  = {}; list.forEach(c => obj[c.chave] = c.valor);
    res.json(obj);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/config', adminAuth, async (req, res) => {
  try {
    const { chave, valor } = req.body;
    await Config.findOneAndUpdate({ chave }, { chave, valor }, { upsert: true });
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── AUTH ADMIN ───────────────────────────────────────────
app.post('/api/auth/admin', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario||!senha) return res.status(400).json({ erro:'Preencha usuário e senha' });
    const a = await Admin.findOne({ usuario, ativo:true });
    if (!a || !await bcrypt.compare(senha, a.senhaHash))
      return res.status(401).json({ erro:'Usuário ou senha incorretos' });
    const token = jwt.sign({ id:a._id, usuario:a.usuario, tipo:'admin', nivel:a.nivel }, JWT_SECRET, { expiresIn:'12h' });
    await registrarLog('auth', `Admin ${usuario} logou`, usuario, getIP(req));
    res.json({ token, nome:a.nome, nivel:a.nivel });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── AUTH CLIENTE ─────────────────────────────────────────
app.post('/api/auth/cliente', loginLimiter, async (req, res) => {
  try {
    const { login, senha } = req.body;
    if (!login||!senha) return res.status(400).json({ erro:'Login e senha obrigatórios' });
    const c = await Cliente.findOne({ login: login.toLowerCase() });
    if (!c || !await bcrypt.compare(senha, c.senhaHash))
      return res.status(401).json({ erro:'Login ou senha incorretos' });
    if (c.banPermanente) return res.status(403).json({ erro:'Conta banida permanentemente. Contacte o suporte.' });
    if (c.bloqueado) return res.status(403).json({ erro:'Conta bloqueada: ' + (c.motivoBloqueio||'Contacte o suporte') });
    const token = jwt.sign({ id:c._id, login:c.login, tipo:'cliente' }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, nome:c.nome, login:c.login, bloqueado:c.bloqueado, emailVerificado:c.emailVerificado, bairro:c.bairro });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── AUTH MERCADO ─────────────────────────────────────────
// CORRIGIDO: antes usava senha em texto puro — agora usa bcrypt
app.post('/api/auth/mercado', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario||!senha) return res.status(400).json({ erro:'Usuário e senha obrigatórios' });
    const m = await Mercado.findOne({ usuario, ativo:true });
    if (!m || !m.senhaHash || !await bcrypt.compare(senha, m.senhaHash))
      return res.status(401).json({ erro:'Credenciais incorretas' });
    const token = jwt.sign({ id:m._id, usuario:m.usuario, tipo:'mercado', mercadoId:m._id }, JWT_SECRET, { expiresIn:'12h' });
    await registrarLog('auth', `Login mercado: ${usuario}`, usuario, getIP(req));
    res.json({ token, nome:m.nome, icone:m.icone, mercadoId:m._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CADASTRO CLIENTE ─────────────────────────────────────
app.post('/api/auth/cadastro', loginLimiter, async (req, res) => {
  try {
    const { nome, login, senha, email, telefone, bairro, notifWhats } = req.body;
    if (!nome||!login||!senha||!telefone)
      return res.status(400).json({ erro:'Nome, login, senha e telefone são obrigatórios' });
    if (senha.length < 6) return res.status(400).json({ erro:'Senha deve ter pelo menos 6 caracteres' });
    const telNorm = normTel(telefone);
    if (telNorm.length < 10) return res.status(400).json({ erro:'Telefone inválido — informe com DDD (ex: 75 99999-9999)' });
    if (await Cliente.findOne({ login: login.toLowerCase() }))
      return res.status(409).json({ erro:'Login já em uso' });
    if (await Cliente.findOne({ telefone: telNorm }))
      return res.status(409).json({ erro:'Número de WhatsApp já cadastrado' });
    const bloq = await telNaBlacklist(telNorm);
    if (bloq) {
      const dias = Math.max(0, Math.ceil((bloq.dataVencimento - Date.now()) / 86400000));
      return res.status(403).json({ erro:`Número impedido — aguarde ${dias} dia(s).`, diasRestantes:dias });
    }
    // Verifica email duplicado apenas se preenchido
    const emailNorm = (email||'').trim().toLowerCase();
    if (emailNorm) {
      if (await Cliente.findOne({ email: emailNorm }))
        return res.status(409).json({ erro:'E-mail já cadastrado. Use outro e-mail ou deixe em branco.' });
    }
    const c = await Cliente.create({
      nome, login: login.toLowerCase(), senhaHash: await bcrypt.hash(senha, 10),
      email: emailNorm || null, telefone: telNorm, bairro: bairro||'', notifWhats: !!notifWhats, ip: getIP(req)
    });
    const token = jwt.sign({ id:c._id, login:c.login, tipo:'cliente' }, JWT_SECRET, { expiresIn:'30d' });
    await registrarLog('cadastro', `Novo cliente: ${login}`, login, getIP(req));
    res.status(201).json({ token, nome:c.nome, login:c.login, mensagem:'Conta criada com sucesso!' });
  } catch(e) {
    // E11000 = índice único violado (email duplicado ou vazio com índice legado)
    if (e.code === 11000) {
      const campo = Object.keys(e.keyValue||{})[0] || 'campo';
      if (campo === 'email') {
        return res.status(409).json({ erro:'E-mail já cadastrado. Deixe o campo de e-mail em branco ou use outro.' });
      }
      if (campo === 'telefone') {
        return res.status(409).json({ erro:'Número de WhatsApp já cadastrado.' });
      }
      return res.status(409).json({ erro:'Dados duplicados — verifique login, e-mail e telefone.' });
    }
    res.status(500).json({ erro: e.message });
  }
});

// ── AUTH/ME ──────────────────────────────────────────────
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    if (req.user.tipo === 'cliente') {
      const c = await Cliente.findById(req.user.id).select('-senhaHash');
      if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
      res.json({ tipo:'cliente', login:c.login, nome:c.nome, email:c.email, telefone:c.telefone, bairro:c.bairro, bloqueado:c.bloqueado, emailVerificado:c.emailVerificado });
    } else {
      const a = await Admin.findById(req.user.id).select('-senhaHash');
      if (!a) return res.status(404).json({ erro:'Admin não encontrado' });
      res.json({ tipo:'admin', usuario:a.usuario, nome:a.nome, nivel:a.nivel });
    }
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── ALTERAR SENHA (self) ─────────────────────────────────
app.post('/api/auth/alterar-senha', authMiddleware, async (req, res) => {
  try {
    const { senhaAtual, novaSenha } = req.body;
    if (!novaSenha || novaSenha.length < 6) return res.status(400).json({ erro:'Nova senha deve ter mínimo 6 caracteres' });
    if (req.user.tipo === 'admin') {
      const a = await Admin.findById(req.user.id);
      if (!a || !await bcrypt.compare(senhaAtual, a.senhaHash)) return res.status(401).json({ erro:'Senha atual incorreta' });
      await Admin.updateOne({ _id:a._id }, { senhaHash: await bcrypt.hash(novaSenha, 12) });
    } else {
      const c = await Cliente.findById(req.user.id);
      if (!c || !await bcrypt.compare(senhaAtual, c.senhaHash)) return res.status(401).json({ erro:'Senha atual incorreta' });
      await Cliente.updateOne({ _id:c._id }, { senhaHash: await bcrypt.hash(novaSenha, 10) });
    }
    res.json({ mensagem:'Senha alterada com sucesso' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── MERCADOS ─────────────────────────────────────────────
app.get('/api/mercados', async (req, res) => {
  try { res.json(await Mercado.find({ ativo:true }).select('-senhaHash')); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/admin/mercados', adminAuth, async (req, res) => {
  try {
    const { nome, icone, endereco, bairro, whatsapp, website, parceiro, plano, usuario, senha, lat, lng } = req.body;
    if (!nome) return res.status(400).json({ erro:'Nome é obrigatório' });
    const dados = { nome, icone:icone||'🏪', endereco:endereco||'', bairro:bairro||'Centro', cidade:req.body.cidade||'Piatã', whatsapp:whatsapp||'', website:website||null, parceiro:!!parceiro, plano:plano||null, lat:lat||null, lng:lng||null };
    if (usuario) dados.usuario = usuario;
    if (senha)   dados.senhaHash = await bcrypt.hash(senha, 10);
    const m = await Mercado.create(dados);
    await registrarLog('admin', `Mercado criado: ${nome}`, req.user.usuario, getIP(req));
    res.status(201).json({ ...m.toObject(), senhaHash:undefined });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    const upd = {};
    ['nome','icone','endereco','bairro','cidade','whatsapp','website','parceiro','plano','lat','lng','ativo','plusCode','nomeGoogleMaps'].forEach(c => {
      if (req.body[c] !== undefined) upd[c] = req.body[c];
    });
    if (req.body.senha) upd.senhaHash = await bcrypt.hash(req.body.senha, 10);
    const m = await Mercado.findByIdAndUpdate(req.params.id, upd, { new:true }).select('-senhaHash');
    if (!m) return res.status(404).json({ erro:'Mercado não encontrado' });
    res.json(m);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    // Remove mercado + todos os preços e promoções vinculados
    const [rMerc, rPrecos, rPromos] = await Promise.all([
      Mercado.findByIdAndDelete(id),
      Preco.deleteMany({ mercadoId: id }),
      Promocao.deleteMany({ mercadoId: id }),
    ]);
    await registrarLog('admin', `Mercado ${id} excluído (${rPrecos.deletedCount} preços, ${rPromos.deletedCount} promos removidos)`, req.user.usuario, getIP(req));
    res.json({ mensagem:'Mercado e dados removidos', precos:rPrecos.deletedCount, promos:rPromos.deletedCount });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── PRODUTOS ─────────────────────────────────────────────
app.get('/api/produtos', async (req, res) => {
  try { res.json(await Produto.find({ ativo:true }).sort({ categoria:1, nome:1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/produtos', adminAuth, async (req, res) => {
  try {
    const { nome, emoji, categoria } = req.body;
    if (!nome) return res.status(400).json({ erro:'Nome é obrigatório' });
    // Bloqueia nomes genéricos — exige marca + tipo de produto
    const nomeNorm = nome.trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');
    const GENERICOS = /^(produto\s*diverso|diversos?|item|mercadoria|outros?|variado|desconhecido|n[aã]o\s*identificad)(\s|$)/i;
    if (GENERICOS.test(nomeNorm)) {
      return res.status(400).json({ erro:'Nome genérico não permitido. Informe marca + tipo do produto. Ex: "Arroz Kicaldo 1kg"' });
    }
    const palavras = nome.trim().split(/\s+/).filter(Boolean);
    if (palavras.length < 2) {
      return res.status(400).json({ erro:'Nome incompleto. Informe marca + tipo do produto. Ex: "Biscoito Adria 200g"' });
    }
    const p = await Produto.create({ nome: nome.trim(), emoji:emoji||'📦', categoria:categoria||'Geral' });
    res.status(201).json(p);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Atualizar produto (emoji, categoria, nome)
app.put('/api/admin/produtos/:id', adminAuth, async (req, res) => {
  try {
    const { nome, emoji, categoria, ativo } = req.body;
    const upd = {};
    if (nome) upd.nome = nome;
    if (emoji) upd.emoji = emoji;
    if (categoria) upd.categoria = categoria;
    if (ativo !== undefined) upd.ativo = ativo;
    const p = await Produto.findByIdAndUpdate(req.params.id, upd, { new: true });
    if (!p) return res.status(404).json({ erro: 'Produto não encontrado' });
    res.json(p);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── SOLICITAÇÃO DE NOVO PRODUTO (cliente via IA) ──────────
// Cliente solicita cadastro de produto detectado pela IA que não existe no catálogo
app.post('/api/produtos/solicitar', authMiddleware, async (req, res) => {
  try {
    if (req.user.tipo !== 'cliente') return res.status(403).json({ erro: 'Apenas clientes' });
    const { nome, categoria, precoVisto, solicitanteLogin } = req.body;
    if (!nome || !nome.trim()) return res.status(400).json({ erro: 'Nome obrigatorio' });

    // Verifica se já existe produto similar
    const jaExiste = await Produto.findOne({ nome: { $regex: nome.trim().split(' ')[0], $options: 'i' }, ativo: true });
    if (jaExiste) return res.status(409).json({ erro: 'Produto similar ja existe: ' + jaExiste.nome, produto: jaExiste });

    // Salva como ocorrência/log para o admin revisar
    await registrarLog('produto_solicitado',
      'Produto solicitado por ' + (solicitanteLogin || req.user.login) + ': "' + nome.trim() + '" (R$ ' + (precoVisto||'?') + ') | Categoria: ' + (categoria||'Geral'),
      solicitanteLogin || req.user.login,
      getIP(req)
    );

    // Notifica admins online em tempo real
    notificarAdmins('produto_solicitado', {
      nome: nome.trim(),
      categoria: categoria || 'Geral',
      precoVisto: precoVisto || null,
      solicitante: solicitanteLogin || req.user.login,
      mensagem: 'Novo produto solicitado: "' + nome.trim() + '" por ' + (solicitanteLogin || req.user.login),
    });

    res.json({ ok: true, mensagem: 'Solicitacao registrada! O admin ira analisar.' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── LISTAR SOLICITAÇÕES DE PRODUTO (admin) ────────────────
app.get('/api/admin/produtos-solicitados', adminAuth, async (req, res) => {
  try {
    const logs = await Log.find({ tipo: 'produto_solicitado' }).sort({ createdAt: -1 }).limit(100);
    res.json(logs);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/produtos/:id', adminAuth, async (req, res) => {
  try {
    await Produto.findByIdAndUpdate(req.params.id, { ativo:false });
    res.json({ mensagem:'Produto removido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Status do catálogo (diagnóstico rápido)
app.get('/api/admin/seed-status', adminAuth, async (req, res) => {
  try {
    const total     = await Produto.countDocuments({ ativo: true });
    const nomesDB   = (await Produto.find({ ativo:true }, 'nome')).map(p => p.nome);
    const nomesSeed = PRODUTOS_SEED.map(p => p.nome);
    const faltando  = nomesSeed.filter(n => !nomesDB.some(d => d.toLowerCase().trim() === n.toLowerCase().trim()));
    res.json({ totalBanco: total, totalSeed: PRODUTOS_SEED.length, faltando: faltando.length, faltandoLista: faltando });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Seed manual (botão no painel admin) — suporta force para reprocessar todos
app.post('/api/admin/seed-produtos', adminAuth, async (req, res) => {
  try {
    const force = req.body?.force === true;

    // 1. Reativar produtos do seed que estejam inativos (ativo:false)
    const todosExistentes = await Produto.find({}, 'nome ativo');
    const inativosSeed = todosExistentes.filter(p => {
      const nomeNorm = p.nome.toLowerCase().replace(/\s+/g,' ').trim();
      const noSeed   = PRODUTOS_SEED.some(s => s.nome.toLowerCase().replace(/\s+/g,' ').trim() === nomeNorm);
      return noSeed && !p.ativo;
    });
    let reativados = 0;
    if (inativosSeed.length) {
      const ids = inativosSeed.map(p => p._id);
      await Produto.updateMany({ _id: { $in: ids } }, { ativo: true });
      reativados = inativosSeed.length;
    }

    // 2. Inserir produtos do seed que não existam no banco (nem inativos)
    const nomesTodos = new Set(todosExistentes.map(p => p.nome.toLowerCase().replace(/\s+/g,' ').trim()));
    const novos      = PRODUTOS_SEED.filter(p => !nomesTodos.has(p.nome.toLowerCase().replace(/\s+/g,' ').trim()));
    let inseridos = 0;
    if (novos.length) {
      await Produto.insertMany(novos, { ordered: false }).catch(()=>{});
      inseridos = novos.length;
    }

    const total = await Produto.countDocuments({ ativo: true });
    const acoes = [inseridos > 0 && `+${inseridos} novos`, reativados > 0 && `${reativados} reativados`].filter(Boolean).join(', ');
    await registrarLog('admin', `Seed produtos: ${acoes||'nenhuma ação'}. Total: ${total}`, req.user.usuario, getIP(req));
    res.json({
      mensagem: (inseridos + reativados) > 0
        ? `✅ ${acoes} ao catálogo!`
        : 'Catálogo já estava completo — nenhum produto novo.',
      novos: inseridos,
      reativados,
      total,
      jaExistiam: todosExistentes.length
    });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── PREÇOS ───────────────────────────────────────────────
app.get('/api/precos', async (req, res) => {
  try {
    res.json(await Preco.find()
      .populate('produtoId','nome emoji categoria')
      .populate('mercadoId','nome icone'));
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/precos', authMiddleware, async (req, res) => {
  try {
    const { produtoId, mercadoId, preco, fonte } = req.body;
    if (!produtoId||!mercadoId||!preco) return res.status(400).json({ erro:'produtoId, mercadoId e preco obrigatórios' });
    // Validar que produtoId e mercadoId são ObjectIds válidos (não "null", "undefined", etc.)
    if (!isObjId(produtoId)) return res.status(400).json({ erro:'produtoId inválido: "' + produtoId + '". Selecione um produto do catálogo.' });
    if (!isObjId(mercadoId)) return res.status(400).json({ erro:'mercadoId inválido: "' + mercadoId + '". Selecione um mercado.' });
    if (!validarPreco(preco)) return res.status(400).json({ erro:'Preço inválido (deve ser positivo e menor que R$ 99.999)' });
    // Plano Básico: limite de 50 produtos (só aplica quando o mercado está atualizando o próprio preço)
    if (req.user.tipo === 'mercado') {
      const mercPlano = await Mercado.findById(req.user.mercadoId);
      const planoNorm = (mercPlano?.plano||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');
      const planoOrd2 = {basico:1,pro:2,premium:3};
      if ((planoOrd2[planoNorm]||0) < 2) {
        const qtdAtual = await Preco.countDocuments({ mercadoId: req.user.mercadoId });
        if (qtdAtual >= 50) return res.status(403).json({ erro:'Limite de 50 produtos atingido no plano Básico. Faça upgrade para o plano Pro para cadastrar produtos ilimitados.' });
      }
    }
    const autor = req.user.tipo === 'admin' ? 'Admin' : (req.user.login || req.user.usuario || 'Mercado');
    const entry = { produtoId, mercadoId, preco:parseFloat(preco), fonte:fonte||req.user.tipo, autor, dataAtu: new Date().toLocaleDateString('pt-BR') };
    const p = await Preco.findOneAndUpdate({ produtoId, mercadoId }, entry, { upsert:true, new:true });
    res.status(201).json(p);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Excluir preço (admin)
app.delete('/api/precos/:produtoId/:mercadoId', adminAuth, async (req, res) => {
  try {
    const { produtoId, mercadoId } = req.params;
    if (!produtoId || produtoId === 'null' || produtoId === 'undefined' ||
        !mercadoId || mercadoId === 'null' || mercadoId === 'undefined') {
      return res.status(400).json({ erro:'IDs inválidos' });
    }
    let deletado = false;
    // Tenta como string primeiro
    const r1 = await Preco.findOneAndDelete({ produtoId, mercadoId });
    if (r1) deletado = true;
    // Tenta com ObjectId explícito se não encontrou
    if (!deletado && isObjId(produtoId) && isObjId(mercadoId)) {
      const r2 = await Preco.findOneAndDelete({
        produtoId: new mongoose.Types.ObjectId(produtoId),
        mercadoId: new mongoose.Types.ObjectId(mercadoId)
      });
      if (r2) deletado = true;
    }
    // Tenta busca mais ampla (produtoId pode estar armazenado como string ou ObjectId)
    if (!deletado) {
      const r3 = await Preco.deleteMany({
        $or: [
          { produtoId: produtoId, mercadoId: mercadoId },
          ...(isObjId(produtoId) && isObjId(mercadoId) ? [
            { produtoId: new mongoose.Types.ObjectId(produtoId), mercadoId: new mongoose.Types.ObjectId(mercadoId) }
          ] : [])
        ]
      });
      if (r3.deletedCount) deletado = true;
    }
    res.json({ ok: true, deletado });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Limpar preço órfão (quando produto foi deletado mas preço persiste)
app.post('/api/admin/limpar-preco-orfao', adminAuth, async (req, res) => {
  try {
    const { produtoId, mercadoId } = req.body;
    if (!produtoId || !mercadoId) return res.status(400).json({ erro:'produtoId e mercadoId obrigatórios' });
    // Deleta usando todas as formas possíveis
    const r = await Preco.deleteMany({
      $or: [
        { produtoId: produtoId, mercadoId: mercadoId },
        ...(isObjId(produtoId) ? [{ produtoId: new mongoose.Types.ObjectId(produtoId), mercadoId: mercadoId }] : []),
        ...(isObjId(mercadoId) ? [{ produtoId: produtoId, mercadoId: new mongoose.Types.ObjectId(mercadoId) }] : []),
        ...(isObjId(produtoId) && isObjId(mercadoId) ? [{ produtoId: new mongoose.Types.ObjectId(produtoId), mercadoId: new mongoose.Types.ObjectId(mercadoId) }] : [])
      ]
    });
    res.json({ ok: true, removidos: r.deletedCount });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Limpar TODOS os preços órfãos (produto não existe mais no catálogo)
app.post('/api/admin/limpar-precos-orfaos', adminAuth, async (req, res) => {
  try {
    const todosPrecos = await Preco.find();
    const produtosIds = new Set((await Produto.find({}, '_id')).map(p => String(p._id)));
    const orfaos = todosPrecos.filter(p => !produtosIds.has(String(p.produtoId)));
    if (orfaos.length) {
      await Preco.deleteMany({ _id: { $in: orfaos.map(p => p._id) } });
    }
    await registrarLog('admin', `Limpeza: ${orfaos.length} preço(s) órfão(s) removidos`, req.user.usuario, getIP(req));
    res.json({ ok: true, removidos: orfaos.length });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── PROMOÇÕES ────────────────────────────────────────────
app.get('/api/promocoes', async (req, res) => {
  try {
    const isAdmin = req.headers.authorization?.startsWith('Bearer ');
    const todas = await Promocao.find({ ativa: true });

    // Parse validade DD/MM/YYYY e desativar expiradas
    const hoje = new Date();
    hoje.setHours(0,0,0,0);
    const expiradas = [];

    const ativas = todas.filter(p => {
      if (!p.validade) return true;
      const partes = p.validade.split('/');
      if (partes.length !== 3) return true;
      const [dd, mm, yyyy] = partes.map(Number);
      const dataVal = new Date(yyyy, mm - 1, dd);
      if (dataVal < hoje) {
        expiradas.push(p._id);
        return false;
      }
      return true;
    });

    // Deleta expiradas do banco (não apenas desativa)
    if (expiradas.length) {
      Promocao.deleteMany({ _id: { $in: expiradas } }).catch(() => {});
      console.log('[Promoções] Deletadas ' + expiradas.length + ' expiradas');
    }

    res.json(ativas);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Admin pode ver todas incluindo inativas
app.get('/api/promocoes/todas', adminAuth, async (req, res) => {
  try { res.json(await Promocao.find().sort({ createdAt: -1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/promocoes', adminAuth, async (req, res) => {
  try {
    const { produtoId, mercadoId, precoNormal, precoPromo, descricao, validade } = req.body;
    if (!mercadoId) return res.status(400).json({ erro:'Selecione o mercado' });
    if (!produtoId) return res.status(400).json({ erro:'Selecione o produto' });
    if (!precoNormal||!precoPromo||!validade) return res.status(400).json({ erro:'Preencha todos os campos obrigatórios' });
    const pr = await Promocao.create({ produtoId, mercadoId, precoNormal:parseFloat(precoNormal), precoPromo:parseFloat(precoPromo), descricao:descricao||'', validade, ativa:true });
    await registrarLog('admin', 'Promoção criada', req.user.usuario, getIP(req));
    res.status(201).json(pr);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Promoção pelo portal do mercado
app.post('/api/mercado/promocoes', authMiddleware, async (req, res) => {
  try {
    if (req.user.tipo !== 'mercado') return res.status(403).json({ erro:'Apenas mercados' });
    // Verifica plano: promoções apenas para Pro e Premium
    const mercDono = await Mercado.findById(req.user.mercadoId);
    const planoMerc = (mercDono?.plano||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');
    const planoOrd = {basico:1,pro:2,premium:3};
    if ((planoOrd[planoMerc]||0) < 2) return res.status(403).json({ erro:'Promoções disponíveis apenas nos planos Pro e Premium. Faça upgrade para acessar este recurso.' });
    const { produtoId, precoNormal, precoPromo, descricao, validade } = req.body;
    if (!produtoId||!precoNormal||!precoPromo||!validade) return res.status(400).json({ erro:'Campos obrigatórios faltando' });
    // Valida data: não aceitar promoções já vencidas
    const partes = (validade||'').split('/');
    if (partes.length === 3) {
      const [dd,mm,yyyy] = partes.map(Number);
      const dataVal = new Date(yyyy, mm-1, dd);
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      if (dataVal < hoje) return res.status(400).json({ erro:'A data de validade não pode ser uma data passada.' });
    }
    const pr = await Promocao.create({ produtoId, mercadoId:req.user.mercadoId, precoNormal:parseFloat(precoNormal), precoPromo:parseFloat(precoPromo), descricao:descricao||'', validade });
    res.status(201).json(pr);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/promocoes/:id/toggle', adminAuth, async (req, res) => {
  try {
    const pr = await Promocao.findById(req.params.id);
    if (!pr) return res.status(404).json({ erro:'Promoção não encontrada' });
    pr.ativa = !pr.ativa; await pr.save();
    res.json(pr);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// DELETE real no MongoDB — CORRIGIDO (antes só filtrava array local)
// Middleware que aceita token de admin OU mercado
function adminOrMercadoAuth(req, res, next){
  authMiddleware(req, res, () => {
    if (req.user.tipo === 'admin' || req.user.tipo === 'mercado') return next();
    return res.status(403).json({ erro: 'Acesso negado' });
  });
}

app.delete('/api/promocoes/:id', adminOrMercadoAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || id === 'undefined' || id === 'null') return res.status(400).json({ erro:'ID inválido' });
    // Tenta como ObjectId primeiro, depois como string
    let promo = null;
    if (isObjId(id)) {
      promo = await Promocao.findById(id);
    }
    if (!promo) {
      // Tenta buscar por _id como string (caso venha formatado diferente)
      promo = await Promocao.findOne({ _id: id });
    }
    if (!promo) return res.status(404).json({ erro:'Promoção não encontrada' });
    // Mercado só pode excluir promoções do próprio mercado
    if (req.user.tipo === 'mercado') {
      const merc = await Mercado.findOne({ login: req.user.login });
      if (!merc || String(promo.mercadoId) !== String(merc._id)) {
        return res.status(403).json({ erro:'Você só pode excluir promoções do seu mercado' });
      }
    }
    await Promocao.findByIdAndDelete(promo._id);
    const autor = req.user.tipo === 'admin' ? req.user.usuario : 'mercado:'+req.user.login;
    await registrarLog('admin', `Promoção ${promo._id} removida por ${autor}`, autor, getIP(req));
    res.json({ mensagem:'Promoção excluída do banco' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── SOLICITAÇÃO DE NOVO PRODUTO (cliente) ────────────────
app.post('/api/solicitacao-produto', authMiddleware, async (req, res) => {
  try {
    const { nome, preco, mercadoId, mercadoNome, obs, autor } = req.body;
    if (!nome) return res.status(400).json({ erro:'Nome do produto obrigatório' });
    const descricao = `Novo produto solicitado: "${nome}" | Preço sugerido: R$ ${preco||'N/A'} | Mercado: ${mercadoNome||'N/A'} | MercadoId: ${mercadoId||''} | Por: ${autor||req.user.login||'anon'}`;
    // Salva com campos estruturados para o admin recuperar sem parsear texto
    await Log.create({
      tipo: 'produto_solicitado',
      descricao,
      usuario: req.user.login || req.user.usuario || 'anon',
      ip: getIP(req),
      mercadoId:   mercadoId   || '',
      mercadoNome: mercadoNome || '',
      preco:       parseFloat(preco) || 0,
      nomeProduto: nome,
    });
    notificarAdmins('produto_solicitado', { nome, preco, mercadoNome, autor: autor||req.user.login });
    res.json({ ok:true, mensagem:'Solicitação registrada!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CONTRIBUIÇÕES ────────────────────────────────────────
app.get('/api/contribuicoes', adminAuth, async (req, res) => {
  try { res.json(await Contribuicao.find().sort({ createdAt:-1 }).limit(200)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/contribuicoes', authMiddleware, async (req, res) => {
  try {
    if (req.user.tipo !== 'cliente') return res.status(403).json({ erro:'Apenas clientes' });
    const { produtoId, mercadoId, preco, tipo, obs } = req.body;
    if (!produtoId||!mercadoId||!preco) return res.status(400).json({ erro:'produtoId, mercadoId e preco obrigatorios' });
    if (!isObjId(String(produtoId))) return res.status(400).json({ erro:'produtoId inválido. Selecione um produto do catálogo.' });
    if (!isObjId(String(mercadoId))) return res.status(400).json({ erro:'mercadoId inválido. Selecione um mercado.' });
    if (!validarPreco(preco)) return res.status(400).json({ erro:'Preco invalido (positivo, menor que R$ 99.999)' });
    const c = await Cliente.findById(req.user.id);
    if (!c || c.bloqueado) return res.status(403).json({ erro:'Conta bloqueada' });
    const contrib = await Contribuicao.create({ tipo:tipo||'texto', produtoId, mercadoId, preco:parseFloat(preco), autor:c.nome, clienteId:c._id, obs:obs||'', ip:getIP(req) });
    notificarAdmins('nova_contribuicao', { id:contrib._id, autor:c.nome });
    res.status(201).json({ mensagem:'Contribuição enviada! Aguarda aprovação.', id:contrib._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/aprovar', adminAuth, async (req, res) => {
  try {
    const c = await Contribuicao.findByIdAndUpdate(req.params.id, { status:'aprovado' }, { new:true });
    if (!c) return res.status(404).json({ erro:'Não encontrada' });
    if (c.produtoId && c.mercadoId && c.preco && isObjId(String(c.produtoId)) && isObjId(String(c.mercadoId))) {
      await Preco.findOneAndUpdate(
        { produtoId:c.produtoId, mercadoId:c.mercadoId },
        { produtoId:c.produtoId, mercadoId:c.mercadoId, preco:c.preco, fonte:'cliente', autor:c.autor, dataAtu:new Date().toLocaleDateString('pt-BR') },
        { upsert:true }
      );
    }
    if (c.clienteId) await Cliente.findByIdAndUpdate(c.clienteId, { $inc:{ totalContribuicoes:1 }, errosConsecutivos:0 });
    res.json({ mensagem:'Aprovado e preço publicado!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/rejeitar', adminAuth, async (req, res) => {
  try {
    const c = await Contribuicao.findByIdAndUpdate(req.params.id, { status:'rejeitado', motivoRecusa:req.body?.motivo||'' }, { new:true });
    if (!c) return res.status(404).json({ erro:'Não encontrada' });
    if (c.clienteId) await Cliente.findByIdAndUpdate(c.clienteId, { $inc:{ contribuicoesRejeitadas:1, errosConsecutivos:1 } });
    res.json({ mensagem:'Rejeitado' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── REPORTS (preço incorreto) ────────────────────────────
app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const { produtoId, mercadoId, motivo, detalhes, precoCorreto, autorOriginal } = req.body;
    if (!produtoId || !mercadoId) return res.status(400).json({ erro: 'produtoId e mercadoId obrigatórios' });

    const reporter = await Cliente.findById(req.user.id);
    if (!reporter) return res.status(404).json({ erro: 'Cliente não encontrado' });

    // 1. Registrar o report como contribuição
    await Contribuicao.create({
      tipo: 'report',
      produtoId, mercadoId,
      preco: precoCorreto || null,
      autor: reporter.nome,
      clienteId: reporter._id,
      obs: `REPORT: ${motivo}. ${detalhes || ''}. Autor original: ${autorOriginal || 'desconhecido'}`,
      status: 'aprovado',
      ip: getIP(req)
    });

    // 2. Se informou preço correto, atualizar o preço no banco
    if (precoCorreto && parseFloat(precoCorreto) > 0 && isObjId(String(produtoId)) && isObjId(String(mercadoId))) {
      await Preco.findOneAndUpdate(
        { produtoId, mercadoId },
        { preco: parseFloat(precoCorreto), fonte: 'report', autor: reporter.nome, dataAtu: new Date().toLocaleDateString('pt-BR') },
        { upsert: true }
      );
    }

    // 3. Verificar se o autor ORIGINAL do preço (quem postou o preço errado) tem 3+ reports em 4 dias
    if (autorOriginal && autorOriginal !== 'Admin' && autorOriginal !== 'admin') {
      const clienteOriginal = await Cliente.findOne({
        $or: [{ nome: autorOriginal }, { login: autorOriginal.toLowerCase() }]
      });
      if (clienteOriginal && !clienteOriginal.bloqueado) {
        // Contar reports contra este cliente nos últimos 4 dias
        const limite4d = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);
        const reportsContra = await Contribuicao.countDocuments({
          tipo: 'report',
          obs: { $regex: autorOriginal, $options: 'i' },
          createdAt: { $gte: limite4d }
        });

        // Incrementar errosConsecutivos
        await Cliente.findByIdAndUpdate(clienteOriginal._id, { $inc: { errosConsecutivos: 1 } });

        if (reportsContra >= 2) { // Este é o 3º (0-indexed: já tinha 2, agora +1 = 3)
          // Bloquear automaticamente
          await Cliente.findByIdAndUpdate(clienteOriginal._id, {
            bloqueado: true,
            motivoBloqueio: `Bloqueio automático: ${reportsContra + 1} preços reportados como incorretos em 4 dias. Contacte o suporte para revisão.`,
            banTemporario: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toLocaleDateString('pt-BR'),
            banPermanente: false
          });

          // Registrar ocorrência para o admin
          await Ocorrencia.create({
            cliente: clienteOriginal.nome,
            clienteLogin: clienteOriginal.login,
            whatsapp: clienteOriginal.telefone,
            mensagem: `⚠️ BLOQUEIO AUTOMÁTICO: "${clienteOriginal.nome}" (${clienteOriginal.login}) bloqueado por ${reportsContra + 1} preços reportados como incorretos em 4 dias. WhatsApp: ${clienteOriginal.telefone || 'não informado'}`,
            status: 'aberto'
          });

          // Notificar admins online
          notificarAdmins('cliente_bloqueado_auto', {
            clienteId: clienteOriginal._id,
            nome: clienteOriginal.nome,
            login: clienteOriginal.login,
            whatsapp: clienteOriginal.telefone,
            reports: reportsContra + 1,
            mensagem: `Cliente "${clienteOriginal.nome}" bloqueado automaticamente por ${reportsContra + 1} reports`
          });

          await registrarLog('auth', `Bloqueio automático: ${clienteOriginal.login} — ${reportsContra + 1} reports em 4 dias`, 'sistema', getIP(req));
        }
      }
    }

    await registrarLog('report', `Report: produtoId=${produtoId}, mercadoId=${mercadoId}, motivo=${motivo}`, reporter.login, getIP(req));
    notificarAdmins('novo_report', { produtoId, mercadoId, motivo, reporter: reporter.nome });

    res.json({ ok: true, mensagem: 'Report enviado! Obrigado por manter os preços corretos.' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CLIENTES (admin) ─────────────────────────────────────
app.get('/api/admin/clientes', adminAuth, async (req, res) => {
  try { res.json(await Cliente.find().select('-senhaHash').sort({ createdAt:-1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/bloquear', adminAuth, async (req, res) => {
  try {
    const { tipo, dias, motivo } = req.body;
    const upd = { bloqueado:true, motivoBloqueio: motivo||'Bloqueado pelo admin' };
    if (tipo === 'temp' && dias) {
      const ate = new Date(); ate.setDate(ate.getDate() + parseInt(dias));
      upd.banTemporario = ate.toLocaleDateString('pt-BR'); upd.banPermanente = false;
      upd.motivoBloqueio = `Ban temporário por ${dias} dias`;
    } else { upd.banPermanente = true; upd.banTemporario = null; }
    const c = await Cliente.findByIdAndUpdate(req.params.id, upd, { new:true }).select('-senhaHash');
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    await registrarLog('admin', `Cliente ${c.login} bloqueado`, req.user.usuario, getIP(req));
    res.json({ mensagem:'Cliente bloqueado', cliente:c });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/desbloquear', adminAuth, async (req, res) => {
  try {
    const c = await Cliente.findByIdAndUpdate(req.params.id, { bloqueado:false, banTemporario:null, banPermanente:false, motivoBloqueio:'', errosConsecutivos:0 }, { new:true }).select('-senhaHash');
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    res.json({ mensagem:'Cliente desbloqueado' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// NOVO: Alterar senha de cliente pelo admin (sem precisar da senha atual)
app.patch('/api/admin/clientes/:id/senha', adminAuth, async (req, res) => {
  try {
    const { novaSenha } = req.body;
    if (!novaSenha || novaSenha.length < 6) return res.status(400).json({ erro:'Senha deve ter mínimo 6 caracteres' });
    const c = await Cliente.findById(req.params.id);
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    await Cliente.updateOne({ _id:c._id }, { senhaHash: await bcrypt.hash(novaSenha, 10) });
    await registrarLog('admin', `Senha de ${c.login} alterada pelo admin`, req.user.usuario, getIP(req));
    res.json({ mensagem:`Senha de ${c.nome} alterada com sucesso` });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// NOVO: Editar dados de cliente pelo admin
app.patch('/api/admin/clientes/:id/editar', adminAuth, async (req, res) => {
  try {
    const upd = {};
    const { nome, email, bairro, telefone } = req.body;
    if (nome     !== undefined) upd.nome   = nome;
    if (email    !== undefined) upd.email  = email;
    if (bairro   !== undefined) upd.bairro = bairro;
    if (telefone !== undefined) upd.telefone = normTel(telefone);
    const c = await Cliente.findByIdAndUpdate(req.params.id, upd, { new:true }).select('-senhaHash');
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    res.json({ mensagem:'Dados atualizados', cliente:c });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Zerar erros consecutivos do cliente
app.patch('/api/admin/clientes/:id/zerar-erros', adminAuth, async (req, res) => {
  try {
    const c = await Cliente.findByIdAndUpdate(
      req.params.id,
      { errosConsecutivos: 0 },
      { new: true }
    ).select('-senhaHash');
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    await registrarLog('admin', `Erros zerados para cliente ${c.nome}`, req.user.usuario, getIP(req));
    res.json({ mensagem:'Erros zerados', cliente:c });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// CORRIGIDO: hard delete + blacklist 2 meses
app.delete('/api/admin/clientes/:id', adminAuth, async (req, res) => {
  try {
    if (!isObjId(req.params.id)) return res.status(400).json({ erro:'ID inválido' });
    const c = await Cliente.findById(req.params.id);
    if (!c) return res.status(404).json({ erro:'Cliente não encontrado' });
    const tel    = normTel(c.telefone);
    const motivo = req.body?.motivo || 'Conta excluída por administrador';
    await Cliente.findByIdAndDelete(req.params.id);
    const vence = new Date(); vence.setMonth(vence.getMonth() + 2);
    await Blacklist.findOneAndUpdate(
      { telefone: tel },
      { telefone:tel, dataInicio:new Date(), dataVencimento:vence, motivo, criadoPor:req.user.usuario, ativo:true },
      { upsert:true }
    );
    await registrarLog('admin', `Cliente ${c.nome} (${tel}) excluído`, req.user.usuario, getIP(req));
    res.json({ mensagem:`Conta de ${c.nome} excluída. Número bloqueado por 2 meses.` });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── ADMINS ───────────────────────────────────────────────
app.get('/api/admin/admins', adminAuth, async (req, res) => {
  // Retorna apenas admins ATIVOS (ativo:true ou campo ausente)
  try { res.json(await Admin.find({ ativo: { $ne: false } }).select('-senhaHash')); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/admin/admins', adminAuth, async (req, res) => {
  try {
    const { nome, usuario, senha, nivel, email } = req.body;
    if (!nome||!usuario||!senha) return res.status(400).json({ erro:'Nome, usuário e senha obrigatórios' });
    // Verifica SOMENTE admins ativos — admins desativados não bloqueiam recriação
    const existeAtivo = await Admin.findOne({ usuario, ativo: { $ne: false } });
    if (existeAtivo) return res.status(409).json({ erro:'Usuário já existe' });
    // Se existe inativo com mesmo nome, reativa em vez de criar novo
    const existeInativo = await Admin.findOne({ usuario });
    if (existeInativo) {
      existeInativo.nome = nome;
      existeInativo.email = email||'';
      existeInativo.nivel = nivel||'admin';
      existeInativo.senhaHash = await bcrypt.hash(senha, 12);
      existeInativo.ativo = true;
      await existeInativo.save();
      const obj = existeInativo.toObject(); delete obj.senhaHash;
      return res.status(200).json(obj);
    }
    const a = await Admin.create({ nome, usuario, email:email||'', nivel:nivel||'admin', senhaHash: await bcrypt.hash(senha, 12), ativo:true });
    res.status(201).json({ ...a.toObject(), senhaHash:undefined });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/admins/:id', adminAuth, async (req, res) => {
  try {
    // Não permite excluir o super admin principal
    const a = await Admin.findById(req.params.id);
    if (!a) return res.status(404).json({ erro:'Admin não encontrado' });
    if (a.nivel === 'super' && a.usuario === 'admin') return res.status(403).json({ erro:'Não é possível excluir o admin principal' });
    // Hard delete para liberar o username para reuso
    await Admin.findByIdAndDelete(req.params.id);
    res.json({ mensagem:'Admin removido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── SOLICITAÇÕES ─────────────────────────────────────────
app.get('/api/admin/solicitacoes', adminAuth, async (req, res) => {
  try { res.json(await Solicitacao.find().sort({ createdAt:-1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/solicitacoes', async (req, res) => {
  try {
    const { mercado, responsavel, whatsapp, email, endereco, bairro, plano, login, senha } = req.body;
    if (!mercado||!responsavel||!whatsapp||!plano)
      return res.status(400).json({ erro:'Campos obrigatórios: mercado, responsavel, whatsapp, plano' });
    const whatsNorm = normTel(whatsapp);
    if (whatsNorm.length < 10) return res.status(400).json({ erro:'WhatsApp inválido — informe com DDD' });
    // Validar login se fornecido
    if (login) {
      const loginExiste = await Mercado.findOne({ usuario: login });
      if (loginExiste) return res.status(409).json({ erro:'Este login já está em uso. Escolha outro.' });
    }
    const sol = await Solicitacao.create({
      mercado, responsavel, whatsapp: whatsNorm, email:email||'',
      loginDesejado: login||'', senhaDesejada: senha||'',
      endereco:endereco||'', bairro:bairro||'', plano
    });
    notificarAdmins('nova_solicitacao', { mercado, responsavel });
    res.status(201).json({ mensagem:'Solicitação enviada! Entraremos em contato pelo WhatsApp.', id:sol._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// CORRIGIDO: usa credenciais escolhidas pelo mercado + envia via WhatsApp
app.patch('/api/admin/solicitacoes/:id/aprovar', adminAuth, async (req, res) => {
  try {
    const sol = await Solicitacao.findById(req.params.id);
    if (!sol) return res.status(404).json({ erro:'Solicitação não encontrada' });
    if (sol.status === 'Aprovado') return res.status(400).json({ erro:'Já aprovada anteriormente' });

    // Usar credenciais escolhidas pelo mercado, ou gerar se não fornecidas
    let loginFinal = sol.loginDesejado;
    let senhaFinal = sol.senhaDesejada;
    if (!loginFinal) {
      const slug = sol.mercado.toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g,'')
        .replace(/[^a-z0-9]/g,'_').replace(/_+/g,'_').substring(0,18);
      loginFinal = `merc_${slug}_${Date.now().toString().slice(-4)}`;
    }
    if (!senhaFinal) {
      senhaFinal = gerarSenha(10);
    }

    // Verificar se login já existe
    const loginExiste = await Mercado.findOne({ usuario: loginFinal });
    if (loginExiste) {
      loginFinal = `${loginFinal}_${Date.now().toString().slice(-4)}`;
    }

    // Criar mercado no banco com senha hasheada
    const novoMercado = await Mercado.create({
      nome: sol.mercado, icone:'🏪', endereco: sol.endereco||'', bairro: sol.bairro||'Centro',
      whatsapp: sol.whatsapp, parceiro:true, plano: sol.plano,
      usuario: loginFinal, senhaHash: await bcrypt.hash(senhaFinal, 10)
    });

    // Atualizar solicitação
    await Solicitacao.findByIdAndUpdate(req.params.id, {
      status:'Aprovado', mercadoId:novoMercado._id,
      credenciais:{ login:loginFinal, senha:senhaFinal }
    });

    // Montar mensagem WhatsApp com credenciais
    const msgWa = `✅ *PreçoCerto* — Cadastro Aprovado!\n\n` +
      `🏪 *Mercado:* ${sol.mercado}\n` +
      `👤 *Login:* ${loginFinal}\n` +
      `🔑 *Senha:* ${senhaFinal}\n\n` +
      `📲 Acesse: ${APP_URL}\n` +
      `Use a opção "Portal do Mercado" na tela inicial.\n` +
      `⚠️ Recomendamos alterar sua senha após o primeiro acesso!`;
    const waNumber = normTel(sol.whatsapp);
    const whatsappLink = waNumber ? `https://wa.me/55${waNumber}?text=${encodeURIComponent(msgWa)}` : null;

    // E-mail opcional (se fornecido)
    if (sol.email) {
      await enviarEmail(sol.email, '✅ PreçoCerto — Seu mercado foi aprovado!',
        `<h2>Parabéns! ${sol.mercado} foi aprovado no PreçoCerto! 🎉</h2>
         <p><b>Login:</b> ${loginFinal}</p>
         <p><b>Senha:</b> ${senhaFinal}</p>
         <p>Acesse: <a href="${APP_URL}">${APP_URL}</a></p>
         <p><i>Altere sua senha após o primeiro acesso.</i></p>`
      );
    }

    await registrarLog('admin', `Aprovado: ${sol.mercado} → ${loginFinal}`, req.user.usuario, getIP(req));
    res.json({
      mensagem:'Aprovado! Mercado criado com sucesso.',
      credenciais:{ login:loginFinal, senha:senhaFinal },
      whatsappLink,
      mercadoId: novoMercado._id
    });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/solicitacoes/:id/recusar', adminAuth, async (req, res) => {
  try {
    await Solicitacao.findByIdAndUpdate(req.params.id, { status:'Recusado' });
    res.json({ mensagem:'Solicitação recusada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── LIMPAR HISTÓRICOS ────────────────────────────────────
app.delete('/api/admin/contribuicoes-processadas', adminAuth, async (req, res) => {
  try {
    const r = await Contribuicao.deleteMany({ status: { $in: ['aprovado', 'rejeitado'] } });
    await registrarLog('admin', `Contribuições processadas limpas: ${r.deletedCount}`, req.user.usuario, getIP(req));
    res.json({ ok: true, removidos: r.deletedCount });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/solicitacoes-processadas', adminAuth, async (req, res) => {
  try {
    const r = await Solicitacao.deleteMany({ status: { $in: ['Aprovado', 'Recusado'] } });
    await registrarLog('admin', `Solicitações processadas limpas: ${r.deletedCount}`, req.user.usuario, getIP(req));
    res.json({ ok: true, removidos: r.deletedCount });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── OCORRÊNCIAS ──────────────────────────────────────────
app.get('/api/ocorrencias', adminAuth, async (req, res) => {
  try { res.json(await Ocorrencia.find().sort({ createdAt:-1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/ocorrencias', async (req, res) => {
  try {
    const oc = await Ocorrencia.create(req.body);
    notificarAdmins('nova_ocorrencia', { id:oc._id, cliente:oc.cliente, tipo: req.body.tipo||'suporte' });
    res.status(201).json(oc);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Salva foto de bug em ocorrência já criada
app.post('/api/ocorrencias/:id/foto', async (req, res) => {
  try {
    const { fotoBase64 } = req.body;
    await Ocorrencia.findByIdAndUpdate(req.params.id, { fotoBase64 });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Admin abre conversa → marca abertaEm e agenda expiração em 48h
app.patch('/api/ocorrencias/:id/abrir', adminAuth, async (req, res) => {
  try {
    const agora = new Date();
    const expira = new Date(agora.getTime() + 48*60*60*1000);
    const admin = req.admin?.login || 'admin';
    await Ocorrencia.findByIdAndUpdate(req.params.id, {
      abertaEm: agora, expiraEm: expira, abertaPor: admin, status: 'lida'
    });
    res.json({ abertaEm: agora, expiraEm: expira });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/ocorrencias/:id/resolver', adminAuth, async (req, res) => {
  try {
    await Ocorrencia.findByIdAndUpdate(req.params.id, { status:'resolvido' });
    res.json({ mensagem:'Resolvido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/ocorrencias/:id', adminAuth, async (req, res) => {
  try {
    await Ocorrencia.findByIdAndDelete(req.params.id);
    res.json({ mensagem:'Removido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Auto-cleanup: remove ocorrências expiradas (48h após abertura)
setInterval(async () => {
  try {
    const r = await Ocorrencia.deleteMany({ expiraEm: { $lt: new Date() } });
    if(r.deletedCount > 0) console.log(`[Auto-cleanup] ${r.deletedCount} ocorrência(s) expirada(s) removida(s)`);
  } catch(e) { console.error('[Auto-cleanup] erro:', e.message); }
}, 15 * 60 * 1000); // a cada 15 min

// ── CHAT SUPORTE ─────────────────────────────────────────
app.get('/api/suporte/chats', adminAuth, async (req, res) => {
  try {
    const msgs = await ChatMsg.find().sort({ createdAt:-1 }).limit(500);
    const grupos = {};
    msgs.reverse().forEach(m => {
      if (!grupos[m.clienteId]) grupos[m.clienteId] = [];
      grupos[m.clienteId].push(m);
    });
    res.json(Object.entries(grupos).map(([clienteId,mensagens]) => ({ clienteId, mensagens, aberto:true })));
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/suporte/mensagens/:clienteId', async (req, res) => {
  try { res.json(await ChatMsg.find({ clienteId:req.params.clienteId }).sort({ createdAt:1 }).limit(100)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/suporte/mensagem', async (req, res) => {
  try {
    const { clienteId, texto, tipo } = req.body;
    if (!texto?.trim()) return res.status(400).json({ erro:'Texto obrigatorio' });
    const msg = await ChatMsg.create({ clienteId:clienteId||'visitante', tipo:tipo||'user', texto:texto.trim(), hora:horaAtual() });
    notificarAdmins('nova_msg_chat', { clienteId:msg.clienteId, texto:msg.texto });
    res.status(201).json(msg);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CLIENTE PEDIU ATENDIMENTO HUMANO ─────────────────────────
app.post('/api/suporte/escalado', async (req, res) => {
  try {
    const { clienteId, dadosCliente } = req.body;
    if (!clienteId) return res.status(400).json({ erro: 'clienteId obrigatorio' });

    await ChatMsg.create({
      clienteId: clienteId||'visitante',
      tipo: 'sistema',
      texto: '[SOLICITOU_ATENDENTE]',
      hora: horaAtual(),
      dadosCliente: dadosCliente||null,
    });

    notificarAdmins('atendimento_solicitado', {
      clienteId,
      dadosCliente,
      mensagem: 'Cliente "' + clienteId + '" solicitou atendimento humano',
    });

    await registrarLog('chat', 'Atendimento solicitado por: ' + clienteId, clienteId, getIP(req));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── CLIENTE SAIU APÓS ESCALAR (sendBeacon) ───────────────────
// Aceita text/plain (sendBeacon) e application/json
app.post('/api/suporte/cliente-saiu', (req, res, next) => {
  const ct = req.headers['content-type']||'';
  if (ct.includes('text/plain') || ct.includes('application/octet-stream')) {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try { req.body = JSON.parse(data); } catch(e) { req.body = {}; }
      next();
    });
  } else next();
}, async (req, res) => {
  try {
    const { clienteId, dadosCliente } = req.body||{};
    if (!clienteId) return res.status(400).json({ erro: 'clienteId obrigatorio' });

    await ChatMsg.create({
      clienteId: clienteId||'visitante',
      tipo: 'sistema',
      texto: '[CLIENTE_SAIU_AGUARDANDO]',
      hora: horaAtual(),
      dadosCliente: dadosCliente||null,
    });

    notificarAdmins('cliente_saiu_aguardando', {
      clienteId,
      dadosCliente,
      mensagem: 'Cliente "' + clienteId + '" saiu e aguarda contato da equipe',
    });

    res.json({ ok: true });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── ADMINS ONLINE (SSE) ──────────────────────────────────
app.get('/api/admins/online/stream', adminAuth, (req, res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();
  adminsOnline.set(String(req.user.id), { usuario:req.user.usuario, res });
  res.write('event: connected\ndata: {}\n\n');
  const hb = setInterval(() => { if (!res.writableEnded) res.write('event: heartbeat\ndata: {}\n\n'); }, 20000);
  req.on('close', () => { clearInterval(hb); adminsOnline.delete(String(req.user.id)); });
});

app.get('/api/admins/online', (req, res) => {
  res.json({ count:adminsOnline.size });
});

// ── LOGS ────────────────────────────────────────────────
app.get('/api/admin/logs', adminAuth, async (req, res) => {
  try { res.json(await Log.find().sort({ createdAt:-1 }).limit(300)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

// Limpar logs do banco (admin)
app.delete('/api/admin/logs', adminAuth, async (req, res) => {
  try {
    const tipo = req.query.tipo; // ?tipo=produto_solicitado ou omite para limpar tudo
    const filtro = tipo ? { tipo } : {};
    const r = await Log.deleteMany(filtro);
    await registrarLog('admin', 'Logs limpos: ' + r.deletedCount + (tipo?' (tipo:'+tipo+')':''), req.user.usuario, getIP(req));
    res.json({ mensagem: r.deletedCount + ' log(s) removido(s)' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Alias (retrocompatibilidade)
app.get('/api/logs', adminAuth, async (req, res) => {
  try { res.json(await Log.find().sort({ createdAt:-1 }).limit(300)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── BLACKLIST ────────────────────────────────────────────
app.get('/api/admin/blacklist', adminAuth, async (req, res) => {
  try {
    const agora = new Date();
    const lista = await Blacklist.find({ ativo:true }).sort({ dataInicio:-1 });
    res.json(lista.map(r => ({ ...r.toObject(), diasRestantes: Math.max(0, Math.ceil((r.dataVencimento-agora)/86400000)) })));
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/blacklist/:id', adminAuth, async (req, res) => {
  try {
    await Blacklist.findByIdAndUpdate(req.params.id, { ativo:false });
    res.json({ mensagem:'Número liberado da blacklist' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// ROTA DE EMERGÊNCIA — força inserção direta no MongoDB
// ═══════════════════════════════════════════════════════════
app.get('/api/fix-catalogo', async (req, res) => {
  const key = req.query.key;
  if (key !== 'piata2026') return res.status(403).send('Proibido');
  try {
    // Pega nomes corretos do seed (versão atual)
    const nomesSeed = new Set(PRODUTOS_SEED.map(p => p.nome.toLowerCase().trim()));

    // Remove produtos cujo nome NÃO está no seed (os velhos com "un" errado etc.)
    const todos = await Produto.find({}, 'nome _id');
    const parasRemover = todos.filter(p => !nomesSeed.has(p.nome.toLowerCase().trim()));
    let removidos = 0;
    if (parasRemover.length) {
      await Produto.deleteMany({ _id: { $in: parasRemover.map(p => p._id) } });
      removidos = parasRemover.length;
    }

    // Remove duplicatas — mantém apenas 1 de cada nome do seed
    for (const seedProd of PRODUTOS_SEED) {
      const encontrados = await Produto.find({ nome: seedProd.nome }).sort({ createdAt: 1 });
      if (encontrados.length > 1) {
        const ids = encontrados.slice(1).map(p => p._id); // remove os extras, mantém o mais antigo
        await Produto.deleteMany({ _id: { $in: ids } });
        removidos += ids.length;
      }
    }

    const total = await Produto.countDocuments({ ativo: true });
    res.send(`<h2>✅ Fix Catálogo</h2>
    <p>Produtos velhos/duplicados removidos: <b>${removidos}</b></p>
    <p>Total banco agora: <b>${total}</b></p>
    <p>Seed tem: <b>${PRODUTOS_SEED.length}</b></p>
    <p><b>Pronto! Recarregue o painel admin.</b></p>`);
  } catch(e) { res.status(500).send('Erro: ' + e.message); }
});



// ── LIMPAR DUPLICATAS ────────────────────────────────────
app.post('/api/admin/limpar-duplicatas', adminAuth, async (req, res) => {
  try {
    let removidos = 0;

    // PASSO 1: Apaga TUDO e reinsere só o seed limpo
    await Produto.deleteMany({});
    const resultado = await Produto.insertMany(PRODUTOS_SEED, { ordered: false });
    const total = await Produto.countDocuments({ ativo: true });

    await registrarLog('admin', `Limpeza catálogo: banco resetado com ${total} produtos do seed.`, req.user.usuario, getIP(req));
    res.json({ removidos: 'todos', total, mensagem: `Catálogo resetado com ${total} produtos limpos do seed.` });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ── SPA FALLBACK ─────────────────────────────────────────

// ─── NF-e / NFC-e: rate limit + cache + scraping SEFAZ ──────────────────────

// Cache em memória: chaveNFe → { mercado, data, itens, consultadoEm }
const nfceCache = new Map();
const NFCE_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h

// Rate limit: ip → { count, resetAt }
const nfceRateLimit = new Map();
const NFCE_MAX_REQ = 5;       // máx 5 por janela
const NFCE_WINDOW  = 60000;   // janela de 1 minuto

function nfceCheckRate(ip) {
  const now = Date.now();
  const entry = nfceRateLimit.get(ip) || { count: 0, resetAt: now + NFCE_WINDOW };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + NFCE_WINDOW; }
  entry.count++;
  nfceRateLimit.set(ip, entry);
  return entry.count <= NFCE_MAX_REQ;
}

// Extrai chave de acesso de 44 dígitos da URL (identifica a nota unicamente)
function extrairChaveNFe(url) {
  const m = url.match(/(\d{44})/);
  return m ? m[1] : url.replace(/[^a-zA-Z0-9]/g,'').substring(0, 60);
}

// Schema para cache persistente no MongoDB
const NfceCacheSchema = new mongoose.Schema({
  chave:       { type: String, required: true, unique: true },
  mercado:     { type: String, default: null },
  data:        { type: String, default: null },
  itens:       { type: Array,  default: [] },
  consultadoEm:{ type: Date,   default: Date.now },
}, { timestamps: false });
const NfceCache = mongoose.model('NfceCache', NfceCacheSchema);

app.post('/api/nfce/consultar', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  const { url } = req.body;

  if (!url || typeof url !== 'string') return res.status(400).json({ erro: 'URL invalida' });

  // ── Rate limit ────────────────────────────────────────────────────────────
  if (!nfceCheckRate(ip)) {
    return res.status(429).json({ erro: 'Limite de consultas atingido. Aguarde 1 minuto.' });
  }

  // ── Valida domínio SEFAZ ─────────────────────────────────────────────────
  const dominiosPermitidos = [
    'nfe.fazenda.gov.br', 'nfce.fazenda.gov.br',
    'sefaz.ba.gov.br',   'nfce.sefaz.ba.gov.br',
    'sefaz.sp.gov.br',   'nfce.sefaz.sp.gov.br',
    'sefaz.rs.gov.br',   'sefaz.mg.gov.br',
    'sefaz.ce.gov.br',   'sefaz.go.gov.br',
    'sefaz.pe.gov.br',   'sefaz.ma.gov.br',
    'portalsped.fazenda.gov.br', 'www.nfe.fazenda.gov.br',
    'nfce.sefaz.al.gov.br', 'nfce.sefaz.to.gov.br',
  ];
  let urlObj;
  try { urlObj = new URL(url); } catch(e) { return res.status(400).json({ erro: 'URL malformada' }); }
  if (!dominiosPermitidos.some(d => urlObj.hostname.endsWith(d))) {
    return res.status(400).json({ erro: 'Dominio nao permitido: ' + urlObj.hostname });
  }

  const chave = extrairChaveNFe(url);

  // ── Cache MongoDB ─────────────────────────────────────────────────────────
  try {
    const cached = await NfceCache.findOne({ chave });
    if (cached) {
      const idade = Date.now() - new Date(cached.consultadoEm).getTime();
      if (idade < NFCE_CACHE_TTL) {
        return res.json({ ok: true, mercado: cached.mercado, data: cached.data, itens: cached.itens, cache: true });
      }
    }
  } catch(_) {}

  // ── Consulta SEFAZ ────────────────────────────────────────────────────────
  try {
    const resp = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
      },
      signal: AbortSignal.timeout(8000), // 8s timeout
    });

    if (!resp.ok) return res.status(502).json({ erro: 'SEFAZ retornou HTTP ' + resp.status });

    const html = await resp.text();

    // ── Extrai nome do estabelecimento ────────────────────────────────────
    const nomeEst = (
      html.match(/class="txtTopo"[^>]*>\s*([^<]{3,60})</) ||
      html.match(/id="u20"[^>]*>([^<]+)</) ||
      html.match(/<div[^>]*txtTopo[^>]*>\s*([^<]{3,60})</) ||
      html.match(/Emitente[^:]*:\s*<[^>]+>([^<]{3,60})</) ||
      []
    )[1]?.trim().replace(/\s+/g,' ') || null;

    // ── Extrai data ───────────────────────────────────────────────────────
    const dataMatch = html.match(/(\d{2}\/\d{2}\/\d{4})/);
    const dataNF = dataMatch ? dataMatch[1] : null;

    const itens = [];

    // Formato 0: SEFAZ BA (www.sefaz.ba.gov.br) — fonteTitulo + Vl. Unit.
    const r0 = /fonteTitulo[^>]*>\s*([^<]{3,80})\s*<\/td>[\s\S]{0,400}?Vl\. Unit\.<\/td>\s*<td>([0-9]+[.,][0-9]{2})<\/td>/gi;
    while ((m = r0.exec(html)) !== null) {
      const nome = m[1].trim().replace(/\s+/g,' ');
      const preco = parseFloat(m[2].replace(/\./g,'').replace(',','.'));
      if (nome.length > 2 && preco > 0 && preco < 9999) itens.push({ produto: nome, preco, qtd: 1 });
    }

    // Formato 1: classe txtTit ou nome_item (portais BA, SP, RS, CE...)
    const r1 = /class="(?:txtTit|nome_item)[^"]*"[^>]*>\s*([^<]{3,80})<[\s\S]{0,500}?(?:Vl\. Unit\.|R\$)\s*([0-9]+[.,][0-9]{2})/gi;
    let m;
    while ((m = r1.exec(html)) !== null) {
      const nome = m[1].trim().replace(/\s+/g,' ');
      const preco = parseFloat(m[2].replace(/\./g,'').replace(',','.'));
      if (nome.length > 2 && preco > 0 && preco < 9999) itens.push({ produto: nome, preco, qtd: 1 });
    }

    // Formato 2: JSON embutido (alguns estados modernos)
    if (!itens.length) {
      const jsonM = html.match(/var\s+\w+\s*=\s*(\{[\s\S]{50,}\})\s*;/);
      if (jsonM) {
        try {
          const obj = JSON.parse(jsonM[1]);
          (obj.det || obj.itens || obj.items || []).forEach(it => {
            const prod = it.prod || it;
            const nome = (prod.xProd || prod.nome || prod.descricao || '').trim();
            const preco = parseFloat(prod.vUnCom || prod.vProd || prod.preco || 0);
            if (nome && preco > 0) itens.push({ produto: nome, preco, qtd: parseFloat(prod.qCom||prod.qtd||1) });
          });
        } catch(_) {}
      }
    }

    // Formato 3: linhas genéricas NOME + valor
    if (!itens.length) {
      const r3 = /<(?:td|div|span)[^>]*>\s*([A-Z][A-Za-z0-9 .\/%-]{4,60})\s*<\/(?:td|div|span)>[\s\S]{0,300}?([0-9]{1,5},[0-9]{2})/gi;
      const vistos = new Set();
      while ((m = r3.exec(html)) !== null) {
        const nome = m[1].trim();
        const preco = parseFloat(m[2].replace(',','.'));
        const chaveItem = nome.toLowerCase().substring(0,10);
        if (!vistos.has(chaveItem) && preco > 0 && preco < 5000 && nome.length > 3) {
          vistos.add(chaveItem);
          itens.push({ produto: nome, preco, qtd: 1 });
        }
      }
    }

    if (!itens.length) {
      return res.json({ ok: false, erro: 'Nao foi possivel extrair itens desta SEFAZ', mercado: nomeEst, data: dataNF });
    }

    // ── Salva no cache MongoDB ────────────────────────────────────────────
    try {
      await NfceCache.findOneAndUpdate(
        { chave },
        { chave, mercado: nomeEst, data: dataNF, itens, consultadoEm: new Date() },
        { upsert: true }
      );
    } catch(_) {}

    return res.json({ ok: true, mercado: nomeEst, data: dataNF, itens, cache: false });

  } catch(e) {
    const isTimeout = e.name === 'TimeoutError' || e.message?.includes('timeout');
    return res.status(502).json({ erro: isTimeout ? 'SEFAZ demorou demais (timeout). Tente novamente.' : 'Erro ao consultar SEFAZ: ' + e.message });
  }
});

// ─── Endpoint: preços colaborativos da NF-e ──────────────────────────────────
// Quando produtos da nota são confirmados, salva como contribuição automática
app.post('/api/nfce/salvar-precos', async (req, res) => {
  const { itens, mercadoId, data } = req.body;
  if (!itens?.length || !mercadoId) return res.status(400).json({ erro: 'Dados incompletos' });

  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const salvos = [];

  for (const item of itens) {
    if (!item.produtoId || !item.preco || item.preco <= 0) continue;
    try {
      const novoPreco = new Preco({
        produtoId: item.produtoId,
        mercadoId,
        preco: item.preco,
        dataAtu: data || new Date().toLocaleDateString('pt-BR'),
        fonte: 'nfce',
        autor: 'Nota Fiscal (NFC-e)',
        ip,
        aprovado: false, // vai para fila de aprovação como qualquer contribuição
      });
      await novoPreco.save();
      salvos.push(item.produtoId);
    } catch(_) {}
  }

  res.json({ ok: true, salvos: salvos.length });
});

// Qualquer rota /api/* não encontrada retorna 404 JSON (não HTML)
app.all('/api/*', (req, res) => {
  res.status(404).json({ erro: 'Rota não encontrada: ' + req.method + ' ' + req.path });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler global — garante que erros em rotas /api retornem JSON
app.use((err, req, res, next) => {
  console.error('[Erro]', err.message);
  if (req.path.startsWith('/api')) {
    res.status(500).json({ erro: err.message || 'Erro interno do servidor' });
  } else {
    res.status(500).sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ═══════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// FILA IA — rotas
// ═══════════════════════════════════════════════════════════

// POST /api/fila-ia — cliente envia foto para a fila
app.post('/api/fila-ia', authMiddleware, async (req, res) => {
  try {
    const { mercadoId, mercadoNome, imagemBase64, mediaType } = req.body;
    if (!mercadoId || !imagemBase64) return res.status(400).json({ erro: 'mercadoId e imagemBase64 obrigatórios' });
    if (!isObjId(mercadoId)) return res.status(400).json({ erro: 'mercadoId inválido' });
    const item = await FilaIA.create({
      clienteId:    req.user._id || null,
      clienteLogin: req.user.login || req.user.usuario || '',
      mercadoId,
      mercadoNome:  mercadoNome || '',
      imagemBase64,
      mediaType:    mediaType || 'image/jpeg',
      status:       'aguardando',
    });
    await registrarLog('fila_ia', `Foto adicionada à fila por ${req.user.login||'?'} — mercado ${mercadoNome||mercadoId}`, req.user.login||'cliente', getIP(req));
    res.status(201).json({ id: item._id, status: 'aguardando', msg: 'Foto adicionada à fila! Será processada automaticamente.' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// GET /api/fila-ia — admin lista fila
app.get('/api/fila-ia', adminAuth, async (req, res) => {
  try {
    const itens = await FilaIA.find().sort({ createdAt: -1 }).limit(200);
    res.json(itens);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// PATCH /api/fila-ia/:id/reprocessar — admin força reprocessamento de um item
app.patch('/api/fila-ia/:id/reprocessar', adminAuth, async (req, res) => {
  try {
    const item = await FilaIA.findById(req.params.id);
    if (!item) return res.status(404).json({ erro: 'Item não encontrado' });
    item.status = 'aguardando';
    item.tentativas = 0;
    item.erroMsg = '';
    await item.save();
    res.json({ ok: true });
    // Dispara processamento imediato em background
    setTimeout(() => processarFilaIA(1), 500);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// DELETE /api/fila-ia/:id — admin remove item da fila
app.delete('/api/fila-ia/:id', adminAuth, async (req, res) => {
  try {
    await FilaIA.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch(                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               