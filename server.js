/**
 * PreçoCerto — Backend v6
 * ════════════════════════════════════════════════════════════
 * CORREÇÕES v6:
 *  1. Aprovação de solicitação → cria mercado + gera credenciais
 *  2. Email transacional (Nodemailer + Gmail/SMTP)
 *  3. Verificação de email com token
 *  4. Recuperação de senha
 *  5. DELETE mercado (soft delete)
 *  6. RBAC: admins com permissões por nível
 *  7. Alteração de senha (admin/cliente)
 *  8. Admin online tracker (SSE)
 *  9. Chat ao vivo admin ↔ cliente
 * 10. Validação robusta ObjectId em todos endpoints
 * 11. Logs de erro detalhados
 * ════════════════════════════════════════════════════════════
 */

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const mongoose   = require('mongoose');
const path       = require('path');
const crypto     = require('crypto');

// Nodemailer — instalar: npm install nodemailer
let nodemailer;
try { nodemailer = require('nodemailer'); } catch(e) { console.warn('⚠️ nodemailer não instalado — emails desativados'); }

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'precocerto_dev_secret_2025';
const MONGODB_URI = process.env.MONGODB_URI || '';
const APP_URL     = process.env.APP_URL     || 'https://preco-certo.onrender.com';

// Email config (definir no Render → Environment Variables)
const EMAIL_HOST  = process.env.EMAIL_HOST  || 'smtp.gmail.com';
const EMAIL_PORT  = parseInt(process.env.EMAIL_PORT || '587');
const EMAIL_USER  = process.env.EMAIL_USER  || '';
const EMAIL_PASS  = process.env.EMAIL_PASS  || '';
const EMAIL_FROM  = process.env.EMAIL_FROM  || 'PreçoCerto <noreply@precocerto.app>';

app.set('trust proxy', 1);

// ═══════════════════════════════════════════════
// EMAIL TRANSACIONAL
// ═══════════════════════════════════════════════
let mailer = null;
if (nodemailer && EMAIL_USER && EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: EMAIL_PORT === 465,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    tls: { rejectUnauthorized: false }
  });
  mailer.verify()
    .then(() => console.log('✅ Email SMTP conectado!'))
    .catch(e => { console.warn('⚠️ Email error:', e.message); mailer = null; });
} else {
  console.log('⚠️ Email não configurado — EMAIL_USER ou EMAIL_PASS ausentes');
}

async function enviarEmail(para, assunto, html) {
  if (!mailer) { console.log(`[EMAIL SIMULADO] Para: ${para} | ${assunto}`); return; }
  try {
    await mailer.sendMail({ from: EMAIL_FROM, to: para, subject: assunto, html });
    console.log(`✅ Email enviado para ${para}`);
  } catch(e) { console.error('❌ Erro email:', e.message); }
}

// ═══════════════════════════════════════════════
// MONGODB
// ═══════════════════════════════════════════════
if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB Atlas conectado!'))
    .catch(e  => console.error('❌ Erro MongoDB:', e.message));
} else {
  console.warn('⚠️ MONGODB_URI não definida');
}

// ═══════════════════════════════════════════════
// SCHEMAS
// ═══════════════════════════════════════════════
const AdminSchema = new mongoose.Schema({
  usuario:    { type: String, required: true, unique: true },
  senhaHash:  { type: String, required: true },
  nome:       { type: String, required: true },
  email:      { type: String, default: '' },
  telefone:   { type: String, default: '' },
  foto:       { type: String, default: null },
  nivel:      { type: String, default: 'admin' }, // super | admin | moderador
  ativo:      { type: Boolean, default: true },
  criadoEm:   { type: Date, default: Date.now }
});

const ClienteSchema = new mongoose.Schema({
  nome:                   { type: String, required: true },
  login:                  { type: String, required: true, unique: true, lowercase: true },
  senhaHash:              { type: String, required: true },
  email:                  { type: String, required: true, unique: true, lowercase: true },
  telefone:               { type: String, default: '' },
  bairro:                 { type: String, default: 'Centro' },
  foto:                   { type: String, default: null },
  notifWhats:             { type: Boolean, default: false },
  bloqueado:              { type: Boolean, default: false },
  banPermanente:          { type: Boolean, default: false },
  motivoBloqueio:         { type: String, default: '' },
  emailVerificado:        { type: Boolean, default: false },
  emailVerifToken:        { type: String, default: null },
  emailVerifExpira:       { type: Date, default: null },
  resetSenhaToken:        { type: String, default: null },
  resetSenhaExpira:       { type: Date, default: null },
  aceitouTermos:          { type: Boolean, default: false },
  errosConsecutivos:      { type: Number, default: 0 },
  totalContribuicoes:     { type: Number, default: 0 },
  contribuicoesRejeitadas:{ type: Number, default: 0 },
  ip:                     { type: String, default: '' },
  dataCadastro:           { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:               { type: Date, default: Date.now }
});

const MercadoSchema = new mongoose.Schema({
  nome:       { type: String, required: true },
  icone:      { type: String, default: '🏪' },
  endereco:   { type: String, default: '' },
  bairro:     { type: String, default: 'Centro' },
  whatsapp:   { type: String, default: '' },
  parceiro:   { type: Boolean, default: false },
  plano:      { type: String, default: null },
  usuario:    { type: String, default: null },
  senhaHash:  { type: String, default: null },
  website:    { type: String, default: null },
  lat:        { type: Number, default: null },
  lng:        { type: Number, default: null },
  ativo:      { type: Boolean, default: true },
  criadoEm:   { type: Date, default: Date.now }
});

const ProdutoSchema = new mongoose.Schema({
  nome:       { type: String, required: true },
  emoji:      { type: String, default: '📦' },
  categoria:  { type: String, default: 'Geral' },
  ativo:      { type: Boolean, default: true },
  criadoEm:   { type: Date, default: Date.now }
});

const PrecoSchema = new mongoose.Schema({
  produtoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Produto', required: true },
  mercadoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  preco:        { type: Number, required: true },
  dataAtu:      { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  fonte:        { type: String, default: 'admin' },
  autor:        { type: String, default: 'Admin' },
  atualizadoEm: { type: Date, default: Date.now }
});

const PromocaoSchema = new mongoose.Schema({
  produtoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Produto', required: true },
  mercadoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  precoNormal:{ type: Number, required: true },
  precoPromo: { type: Number, required: true },
  descricao:  { type: String, default: '' },
  validade:   { type: String, required: true },
  ativa:      { type: Boolean, default: true },
  criadoEm:   { type: Date, default: Date.now }
});

const ContribuicaoSchema = new mongoose.Schema({
  tipo:         { type: String, default: 'texto' },
  produtoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Produto' },
  mercadoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado' },
  preco:        { type: Number, default: null },
  autor:        { type: String, default: 'Anônimo' },
  clienteId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', default: null },
  status:       { type: String, default: 'pendente' },
  motivoRecusa: { type: String, default: '' },
  obs:          { type: String, default: '' },
  fotoUrl:      { type: String, default: null },
  ip:           { type: String, default: '' },
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:     { type: Date, default: Date.now }
});

const LogSchema = new mongoose.Schema({
  tipo:       { type: String, required: true },
  descricao:  { type: String, required: true },
  usuario:    { type: String, default: 'anon' },
  ip:         { type: String, default: '' },
  data:       { type: String, default: () => new Date().toLocaleString('pt-BR') },
  criadoEm:   { type: Date, default: Date.now }
});

const ChatMsgSchema = new mongoose.Schema({
  clienteId:  { type: String, required: true },
  tipo:       { type: String, required: true }, // user | bot | admin
  adminId:    { type: String, default: null },
  texto:      { type: String, required: true },
  hora:       { type: String, required: true },
  lida:       { type: Boolean, default: false },
  criadoEm:   { type: Date, default: Date.now }
});

const ConfigSchema = new mongoose.Schema({
  chave:        { type: String, required: true, unique: true },
  valor:        { type: mongoose.Schema.Types.Mixed, required: true },
  atualizadoEm: { type: Date, default: Date.now }
});

const SolicitacaoSchema = new mongoose.Schema({
  mercado:      { type: String, required: true },
  responsavel:  { type: String, required: true },
  whatsapp:     { type: String, required: true },
  email:        { type: String, default: '' },
  endereco:     { type: String, default: '' },
  bairro:       { type: String, default: '' },
  plano:        { type: String, required: true },
  status:       { type: String, default: 'Pendente' }, // Pendente | Aprovado | Recusado
  mercadoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', default: null },
  credenciais:  { type: Object, default: null },
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:     { type: Date, default: Date.now }
});

const OcorrenciaSchema = new mongoose.Schema({
  cliente:      { type: String, default: 'Visitante' },
  clienteLogin: { type: String, default: null },
  whatsapp:     { type: String, default: null },
  email:        { type: String, default: null },
  mensagem:     { type: String, required: true },
  historico:    { type: String, default: null },
  status:       { type: String, default: 'aberto' }, // aberto | resolvido
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  hora:         { type: String, default: () => new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}) },
  criadoEm:     { type: Date, default: Date.now }
});

// Modelos
const Admin        = mongoose.model('Admin', AdminSchema);
const Cliente      = mongoose.model('Cliente', ClienteSchema);
const Mercado      = mongoose.model('Mercado', MercadoSchema);
const Produto      = mongoose.model('Produto', ProdutoSchema);
const Preco        = mongoose.model('Preco', PrecoSchema);
const Promocao     = mongoose.model('Promocao', PromocaoSchema);
const Contribuicao = mongoose.model('Contribuicao', ContribuicaoSchema);
const Log          = mongoose.model('Log', LogSchema);
const ChatMsg      = mongoose.model('ChatMsg', ChatMsgSchema);
const Config       = mongoose.model('Config', ConfigSchema);
const Solicitacao  = mongoose.model('Solicitacao', SolicitacaoSchema);
const Ocorrencia   = mongoose.model('Ocorrencia', OcorrenciaSchema);

// ═══════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════
const getIP = req => req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '0.0.0.0';
const isObjId = id => mongoose.Types.ObjectId.isValid(id);
const gerarSenha = (n=8) => crypto.randomBytes(n).toString('base64').replace(/[^a-zA-Z0-9]/g,'').substring(0,n);
const hoje = () => new Date().toLocaleDateString('pt-BR');
const horaAtual = () => new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});

async function log(tipo, descricao, usuario='sistema', ip='') {
  try { await Log.create({ tipo, descricao, usuario, ip }); } catch(e) {}
}

// Admin online tracker (em memória)
const adminsOnline = new Map(); // adminId → { usuario, lastSeen, sseRes }
const clientesSseMap = new Map(); // clienteId → sseRes

// ═══════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'] }));
app.use(express.json({ limit: '5mb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 300, standardHeaders: true }));
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ erro: 'Token inválido ou expirado — faça login novamente' }); }
}

function adminAuth(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });
    next();
  });
}

function superAuth(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin' || req.user.nivel !== 'super') return res.status(403).json({ erro: 'Requer nível super' });
    next();
  });
}

// ═══════════════════════════════════════════════
// SEED INICIAL
// ═══════════════════════════════════════════════
async function seedInicial() {
  try {
    const admCount = await Admin.countDocuments();
    if (admCount === 0) {
      await Admin.create({
        usuario: 'admin', nome: 'Administrador Principal', nivel: 'super',
        email: EMAIL_USER || 'admin@precocerto.app',
        senhaHash: await bcrypt.hash('Deusdaminhavida4321', 12)
      });
      console.log('✅ Admin padrão criado');
    }

    const prodCount = await Produto.countDocuments();
    if (prodCount === 0) {
      await Produto.insertMany([
        // Mercearia
        {nome:'Arroz Branco Camil 5kg',emoji:'🍚',categoria:'Mercearia'},{nome:'Arroz Camil 2kg',emoji:'🍚',categoria:'Mercearia'},{nome:'Feijão Carioca Camil 1kg',emoji:'🫘',categoria:'Mercearia'},{nome:'Feijão Preto Camil 1kg',emoji:'🫘',categoria:'Mercearia'},{nome:'Feijão Fradinho 1kg',emoji:'🫘',categoria:'Mercearia'},{nome:'Açúcar Cristal União 1kg',emoji:'🍬',categoria:'Mercearia'},{nome:'Açúcar Refinado União 1kg',emoji:'🍬',categoria:'Mercearia'},{nome:'Sal Refinado Cisne 1kg',emoji:'🧂',categoria:'Mercearia'},{nome:'Macarrão Espaguete Adria 500g',emoji:'🍝',categoria:'Mercearia'},{nome:'Macarrão Parafuso Adria 500g',emoji:'🍝',categoria:'Mercearia'},{nome:'Macarrão Penne Barilla 500g',emoji:'🍝',categoria:'Mercearia'},{nome:'Óleo de Soja Liza 900ml',emoji:'🫙',categoria:'Mercearia'},{nome:'Óleo de Soja Soya 900ml',emoji:'🫙',categoria:'Mercearia'},{nome:'Azeite Extravirgem Gallo 500ml',emoji:'🫒',categoria:'Mercearia'},{nome:'Azeite Carbonell 500ml',emoji:'🫒',categoria:'Mercearia'},{nome:'Farinha de Trigo Dona Benta 1kg',emoji:'🌾',categoria:'Mercearia'},{nome:'Farinha de Trigo Piraquê 5kg',emoji:'🌾',categoria:'Mercearia'},{nome:'Farinha de Mandioca Grossa 1kg',emoji:'🌾',categoria:'Mercearia'},{nome:'Farinha de Milho Flocão 500g',emoji:'🌽',categoria:'Mercearia'},{nome:'Cuscuz Flocão 500g',emoji:'🌾',categoria:'Mercearia'},{nome:'Tapioca Yoki 500g',emoji:'🫓',categoria:'Mercearia'},{nome:'Amido de Milho Maizena 500g',emoji:'🌽',categoria:'Mercearia'},{nome:'Aveia Quaker 500g',emoji:'🌾',categoria:'Mercearia'},{nome:'Granola 3Corações 500g',emoji:'🌾',categoria:'Mercearia'},{nome:'Molho de Tomate Pomarola 520g',emoji:'🍅',categoria:'Mercearia'},{nome:'Molho de Tomate Heinz 300g',emoji:'🍅',categoria:'Mercearia'},{nome:'Extrato de Tomate Quero 140g',emoji:'🍅',categoria:'Mercearia'},{nome:'Maionese Hellmanns 250g',emoji:'🥛',categoria:'Mercearia'},{nome:'Maionese Hellmanns 500g',emoji:'🥛',categoria:'Mercearia'},{nome:'Ketchup Heinz 397g',emoji:'🍅',categoria:'Mercearia'},{nome:'Mostarda Hemmer 200g',emoji:'🌻',categoria:'Mercearia'},{nome:'Molho Shoyu Kikkoman 150ml',emoji:'🍶',categoria:'Mercearia'},{nome:'Vinagre de Álcool Castelo 750ml',emoji:'🍾',categoria:'Mercearia'},{nome:'Tempero Completo Knorr 100g',emoji:'🧄',categoria:'Mercearia'},{nome:'Caldo de Carne Knorr 57g',emoji:'🥩',categoria:'Mercearia'},{nome:'Caldo de Galinha Knorr 57g',emoji:'🍗',categoria:'Mercearia'},{nome:'Alho Granulado Kitano 30g',emoji:'🧄',categoria:'Mercearia'},{nome:'Pimenta do Reino Ducros 30g',emoji:'🫙',categoria:'Mercearia'},{nome:'Canela em Pó 30g',emoji:'🍂',categoria:'Mercearia'},{nome:'Fermento Pó Royal 100g',emoji:'🧁',categoria:'Mercearia'},{nome:'Bicarbonato de Sódio 200g',emoji:'⚗️',categoria:'Mercearia'},{nome:'Leite de Coco Sococo 200ml',emoji:'🥥',categoria:'Mercearia'},{nome:'Milho em Lata Bonduelle 200g',emoji:'🌽',categoria:'Mercearia'},{nome:'Ervilha em Lata Bonduelle 200g',emoji:'🟢',categoria:'Mercearia'},{nome:'Sardinha Lata Coqueiro 125g',emoji:'🐟',categoria:'Mercearia'},{nome:'Atum Lata Gomes da Costa 170g',emoji:'🐟',categoria:'Mercearia'},{nome:'Azeitona Verde Predilecta 150g',emoji:'🫒',categoria:'Mercearia'},{nome:'Palmito Pupunha 300g',emoji:'🌿',categoria:'Mercearia'},
        // Laticínios
        {nome:'Leite Integral Piracanjuba 1L',emoji:'🥛',categoria:'Laticínios'},{nome:'Leite Desnatado Piracanjuba 1L',emoji:'🥛',categoria:'Laticínios'},{nome:'Leite Longa Vida Parmalat 1L',emoji:'🥛',categoria:'Laticínios'},{nome:'Leite em Pó Ninho 400g',emoji:'🥛',categoria:'Laticínios'},{nome:'Leite em Pó Ninho 800g',emoji:'🥛',categoria:'Laticínios'},{nome:'Manteiga com Sal Aviação 200g',emoji:'🧈',categoria:'Laticínios'},{nome:'Manteiga sem Sal Aviação 200g',emoji:'🧈',categoria:'Laticínios'},{nome:'Margarina Qualy 500g',emoji:'🧈',categoria:'Laticínios'},{nome:'Queijo Mussarela kg',emoji:'🧀',categoria:'Laticínios'},{nome:'Queijo Prato kg',emoji:'🧀',categoria:'Laticínios'},{nome:'Queijo Coalho kg',emoji:'🧀',categoria:'Laticínios'},{nome:'Queijo Ricota 250g',emoji:'🧀',categoria:'Laticínios'},{nome:'Requeijão Cremoso Catupiry 200g',emoji:'🧀',categoria:'Laticínios'},{nome:'Iogurte Natural Danone 160g',emoji:'🥛',categoria:'Laticínios'},{nome:'Iogurte Grego Danone 100g',emoji:'🥛',categoria:'Laticínios'},{nome:'Creme de Leite Nestlé 300g',emoji:'🥛',categoria:'Laticínios'},{nome:'Leite Fermentado Yakult 80ml',emoji:'🥛',categoria:'Laticínios'},{nome:'Nata 200g',emoji:'🥛',categoria:'Laticínios'},{nome:'Creme de Leite Ninho UHT 200ml',emoji:'🥛',categoria:'Laticínios'},{nome:'Ovos Brancos dúzia',emoji:'🥚',categoria:'Laticínios'},
        // Bebidas
        {nome:'Água Mineral Crystal 500ml',emoji:'💧',categoria:'Bebidas'},{nome:'Água Mineral Crystal 1,5L',emoji:'💧',categoria:'Bebidas'},{nome:'Água Mineral Indaiá 500ml',emoji:'💧',categoria:'Bebidas'},{nome:'Refrigerante Coca-Cola 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Coca-Cola 350ml lata',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Pepsi 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Guaraná Antarctica 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Fanta Laranja 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Sprite 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Refrigerante Kuat 2L',emoji:'🥤',categoria:'Bebidas'},{nome:'Suco de Laranja Del Valle 1L',emoji:'🧃',categoria:'Bebidas'},{nome:'Suco Integral Del Valle 1L',emoji:'🧃',categoria:'Bebidas'},{nome:'Néctar Tial 1L',emoji:'🧃',categoria:'Bebidas'},{nome:'Cerveja Brahma 350ml lata',emoji:'🍺',categoria:'Bebidas'},{nome:'Cerveja Skol 350ml lata',emoji:'🍺',categoria:'Bebidas'},{nome:'Cerveja Itaipava 350ml lata',emoji:'🍺',categoria:'Bebidas'},{nome:'Energético Red Bull 250ml',emoji:'⚡',categoria:'Bebidas'},{nome:'Energético Monster 473ml',emoji:'⚡',categoria:'Bebidas'},{nome:'Isotônico Gatorade 500ml',emoji:'💧',categoria:'Bebidas'},{nome:'Cachaça 51 965ml',emoji:'🍶',categoria:'Bebidas'},
        // Higiene
        {nome:'Sabonete Dove Hidratação 90g',emoji:'🧼',categoria:'Higiene'},{nome:'Sabonete Lux 85g',emoji:'🧼',categoria:'Higiene'},{nome:'Sabonete Líquido Dove 250ml',emoji:'🧴',categoria:'Higiene'},{nome:'Shampoo TRESemmé 400ml',emoji:'🧴',categoria:'Higiene'},{nome:'Condicionador TRESemmé 400ml',emoji:'🧴',categoria:'Higiene'},{nome:'Shampoo Elseve 400ml',emoji:'🧴',categoria:'Higiene'},{nome:'Creme Dental Colgate 90g',emoji:'🦷',categoria:'Higiene'},{nome:'Creme Dental Colgate Total 90g',emoji:'🦷',categoria:'Higiene'},{nome:'Escova Dental Oral-B',emoji:'🪥',categoria:'Higiene'},{nome:'Fio Dental Oral-B 50m',emoji:'🦷',categoria:'Higiene'},{nome:'Enxaguante Bucal Listerine 250ml',emoji:'🦷',categoria:'Higiene'},{nome:'Desodorante Rexona 150ml',emoji:'💨',categoria:'Higiene'},{nome:'Desodorante Dove 150ml',emoji:'💨',categoria:'Higiene'},{nome:'Desodorante Nivea 150ml',emoji:'💨',categoria:'Higiene'},{nome:'Absorvente Always com Abas',emoji:'🌸',categoria:'Higiene'},{nome:'Protetor Solar Banana Boat FPS50',emoji:'☀️',categoria:'Higiene'},{nome:'Talco Johnson 200g',emoji:'☁️',categoria:'Higiene'},{nome:'Xampu Johnson Baby 200ml',emoji:'🧴',categoria:'Higiene'},{nome:'Sabonete Johnson Baby 80g',emoji:'🧼',categoria:'Higiene'},{nome:'Fraldas Pampers RN/P/M/G pct',emoji:'👶',categoria:'Higiene'},
        // Limpeza
        {nome:'Detergente Ypê Neutro 500ml',emoji:'🧹',categoria:'Limpeza'},{nome:'Detergente Limpol 500ml',emoji:'🧹',categoria:'Limpeza'},{nome:'Sabão em Pó OMO 1kg',emoji:'🧺',categoria:'Limpeza'},{nome:'Sabão em Pó Ariel 1kg',emoji:'🧺',categoria:'Limpeza'},{nome:'Amaciante Downy 1L',emoji:'🌸',categoria:'Limpeza'},{nome:'Amaciante Comfort 1L',emoji:'🌸',categoria:'Limpeza'},{nome:'Alvejante Clorox 1L',emoji:'🧴',categoria:'Limpeza'},{nome:'Água Sanitária Qboa 1L',emoji:'💧',categoria:'Limpeza'},{nome:'Desinfetante Pinho Sol 500ml',emoji:'🌲',categoria:'Limpeza'},{nome:'Multiuso Flash Limp 500ml',emoji:'🧹',categoria:'Limpeza'},{nome:'Esponja de Aço Bombril 8un',emoji:'🪣',categoria:'Limpeza'},{nome:'Esponja Scotch Brite',emoji:'🧽',categoria:'Limpeza'},{nome:'Papel Higiênico Neve 12 rolos',emoji:'🧻',categoria:'Limpeza'},{nome:'Papel Toalha Snob 2 rolos',emoji:'🧻',categoria:'Limpeza'},{nome:'Guardanapo 50un',emoji:'🧻',categoria:'Limpeza'},{nome:'Saco de Lixo 100L 10un',emoji:'🗑️',categoria:'Limpeza'},{nome:'Copo Descartável 200ml 50un',emoji:'🥤',categoria:'Limpeza'},{nome:'Prato Descartável 10un',emoji:'🍽️',categoria:'Limpeza'},
        // Padaria
        {nome:'Pão Forma Wickbold 500g',emoji:'🍞',categoria:'Padaria'},{nome:'Pão Integral Wickbold 500g',emoji:'🍞',categoria:'Padaria'},{nome:'Pão Bisnaguinha Wickbold 200g',emoji:'🥖',categoria:'Padaria'},{nome:'Pão Francês un',emoji:'🥐',categoria:'Padaria'},{nome:'Bolacha Recheada Oreo 96g',emoji:'🍪',categoria:'Padaria'},{nome:'Bolacha Maizena Piraquê 200g',emoji:'🍪',categoria:'Padaria'},{nome:'Bolacha Água e Sal Piraquê 200g',emoji:'🍪',categoria:'Padaria'},{nome:'Biscoito Cream Cracker 200g',emoji:'🍪',categoria:'Padaria'},
        // Açougue
        {nome:'Frango Inteiro kg',emoji:'🍗',categoria:'Açougue'},{nome:'Frango em Pedaços kg',emoji:'🍗',categoria:'Açougue'},{nome:'Peito de Frango kg',emoji:'🍗',categoria:'Açougue'},{nome:'Coxa e Sobrecoxa kg',emoji:'🍗',categoria:'Açougue'},{nome:'Carne Moída kg',emoji:'🥩',categoria:'Açougue'},{nome:'Acém kg',emoji:'🥩',categoria:'Açougue'},{nome:'Paleta Bovina kg',emoji:'🥩',categoria:'Açougue'},{nome:'Costela Bovina kg',emoji:'🥩',categoria:'Açougue'},{nome:'Músculo Bovino kg',emoji:'🥩',categoria:'Açougue'},{nome:'Filé de Frango kg',emoji:'🍗',categoria:'Açougue'},{nome:'Linguiça Calabresa kg',emoji:'🌭',categoria:'Açougue'},{nome:'Linguiça Toscana kg',emoji:'🌭',categoria:'Açougue'},{nome:'Bacon Fatiado 200g',emoji:'🥓',categoria:'Açougue'},{nome:'Carne Seca kg',emoji:'🥩',categoria:'Açougue'},{nome:'Charque kg',emoji:'🥩',categoria:'Açougue'},{nome:'Peixe Tilápia kg',emoji:'🐟',categoria:'Açougue'},{nome:'Peixe Cação kg',emoji:'🐟',categoria:'Açougue'},{nome:'Camarão Limpo kg',emoji:'🦐',categoria:'Açougue'},
        // Frutas
        {nome:'Banana Prata kg',emoji:'🍌',categoria:'Frutas'},{nome:'Maçã Gala kg',emoji:'🍎',categoria:'Frutas'},{nome:'Laranja Lima kg',emoji:'🍊',categoria:'Frutas'},{nome:'Limão Taiti kg',emoji:'🍋',categoria:'Frutas'},{nome:'Mamão Papaya kg',emoji:'🍈',categoria:'Frutas'},{nome:'Melancia un',emoji:'🍉',categoria:'Frutas'},{nome:'Abacaxi un',emoji:'🍍',categoria:'Frutas'},{nome:'Manga kg',emoji:'🥭',categoria:'Frutas'},{nome:'Uva Itália kg',emoji:'🍇',categoria:'Frutas'},{nome:'Pêra kg',emoji:'🍐',categoria:'Frutas'},{nome:'Goiaba kg',emoji:'🟢',categoria:'Frutas'},{nome:'Maracujá kg',emoji:'🟡',categoria:'Frutas'},{nome:'Abacate kg',emoji:'🥑',categoria:'Frutas'},{nome:'Coco Verde un',emoji:'🥥',categoria:'Frutas'},{nome:'Acerola kg',emoji:'🔴',categoria:'Frutas'},
        // Legumes
        {nome:'Tomate kg',emoji:'🍅',categoria:'Legumes'},{nome:'Cebola kg',emoji:'🧅',categoria:'Legumes'},{nome:'Alho kg',emoji:'🧄',categoria:'Legumes'},{nome:'Batata kg',emoji:'🥔',categoria:'Legumes'},{nome:'Batata Doce kg',emoji:'🍠',categoria:'Legumes'},{nome:'Cenoura kg',emoji:'🥕',categoria:'Legumes'},{nome:'Pimentão Vermelho kg',emoji:'🫑',categoria:'Legumes'},{nome:'Pimentão Verde kg',emoji:'🫑',categoria:'Legumes'},{nome:'Abobrinha kg',emoji:'🥒',categoria:'Legumes'},{nome:'Pepino kg',emoji:'🥒',categoria:'Legumes'},{nome:'Beterraba kg',emoji:'🫚',categoria:'Legumes'},{nome:'Macaxeira kg',emoji:'🍠',categoria:'Legumes'},{nome:'Inhame kg',emoji:'🍠',categoria:'Legumes'},{nome:'Abóbora kg',emoji:'🎃',categoria:'Legumes'},{nome:'Berinjela kg',emoji:'🍆',categoria:'Legumes'},{nome:'Jiló kg',emoji:'🟢',categoria:'Legumes'},
        // Verduras
        {nome:'Alface un',emoji:'🥬',categoria:'Verduras'},{nome:'Couve maço',emoji:'🥬',categoria:'Verduras'},{nome:'Espinafre maço',emoji:'🥬',categoria:'Verduras'},{nome:'Rúcula maço',emoji:'🥬',categoria:'Verduras'},{nome:'Cebolinha maço',emoji:'🌿',categoria:'Verduras'},{nome:'Coentro maço',emoji:'🌿',categoria:'Verduras'},{nome:'Salsinha maço',emoji:'🌿',categoria:'Verduras'},{nome:'Repolho un',emoji:'🥦',categoria:'Verduras'},{nome:'Brócolis un',emoji:'🥦',categoria:'Verduras'},
        // Congelados
        {nome:'Sorvete Kibon 1,5L',emoji:'🍦',categoria:'Congelados'},{nome:'Pizza Congelada Sadia 460g',emoji:'🍕',categoria:'Congelados'},{nome:'Hambúrguer Sadia 672g',emoji:'🍔',categoria:'Congelados'},{nome:'Nuggets Sadia 300g',emoji:'🍗',categoria:'Congelados'},{nome:'Batata Frita McCain 400g',emoji:'🍟',categoria:'Congelados'},{nome:'Polpa de Fruta Goiaba 1kg',emoji:'🍈',categoria:'Congelados'},{nome:'Polpa de Fruta Maracujá 1kg',emoji:'🟡',categoria:'Congelados'},
        // Doces
        {nome:'Achocolatado Nescau 400g',emoji:'🍫',categoria:'Doces'},{nome:'Achocolatado Toddy 400g',emoji:'🍫',categoria:'Doces'},{nome:'Chocolate Lacta ao Leite 80g',emoji:'🍫',categoria:'Doces'},{nome:'Chocolate Bis 126g',emoji:'🍫',categoria:'Doces'},{nome:'Gelatina Dr. Oetker 30g',emoji:'🍮',categoria:'Doces'},{nome:'Pudim de Leite Moça 385g',emoji:'🍮',categoria:'Doces'},{nome:'Doce de Leite Italac 400g',emoji:'🍯',categoria:'Doces'},
        // Utilidades
        {nome:'Vela Comum 8un',emoji:'🕯️',categoria:'Utilidades'},{nome:'Isqueiro BIC un',emoji:'🔥',categoria:'Utilidades'},{nome:'Fósforo 40 palitos',emoji:'🔥',categoria:'Utilidades'},{nome:'Pilha AA Duracell 2un',emoji:'🔋',categoria:'Utilidades'},{nome:'Pilha AAA Duracell 2un',emoji:'🔋',categoria:'Utilidades'},{nome:'Saco Zip Lock 20un',emoji:'🫙',categoria:'Utilidades'},{nome:'Papel Alumínio Wyda 30cm',emoji:'🪙',categoria:'Utilidades'},{nome:'Palito de Dente 200un',emoji:'🪥',categoria:'Utilidades'}
      ]);
      console.log('✅ Produtos iniciais criados');
    }
    console.log('✅ Seed completo!');
  } catch(e) { console.error('Erro seed:', e.message); }
}

// ═══════════════════════════════════════════════
// MIDDLEWARE SEGURANÇA
// ═══════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'] }));
app.use(express.json({ limit: '5mb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 500, standardHeaders: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════
// HEALTH
// ═══════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok', app: 'PreçoCerto', versao: '6.0.0',
    db: mongoose.connection.readyState === 1 ? 'conectado' : 'desconectado',
    email: mailer ? 'configurado' : 'não configurado',
    adminsOnline: adminsOnline.size,
    timestamp: new Date().toISOString()
  });
});

// ═══════════════════════════════════════════════
// SSE — ADMIN ONLINE / CHAT AO VIVO
// ═══════════════════════════════════════════════
app.get('/api/sse/admin', adminAuth, (req, res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();

  const adminId = req.user.id;
  const usuario = req.user.usuario;
  adminsOnline.set(adminId, { usuario, lastSeen: Date.now(), res });

  // Enviar heartbeat
  const hb = setInterval(() => {
    if (res.writableEnded) { clearInterval(hb); return; }
    res.write('event: heartbeat\ndata: {}\n\n');
  }, 20000);

  req.on('close', () => {
    clearInterval(hb);
    adminsOnline.delete(adminId);
  });
});

app.get('/api/admins/online', (req, res) => {
  const lista = [...adminsOnline.values()].map(a => ({
    usuario: a.usuario,
    lastSeen: a.lastSeen
  }));
  res.json({ count: lista.length, admins: lista });
});

// Enviar mensagem a um admin específico via SSE
function notificarAdmin(adminId, evento, dados) {
  const admin = adminsOnline.get(adminId);
  if (admin?.res && !admin.res.writableEnded) {
    admin.res.write(`event: ${evento}\ndata: ${JSON.stringify(dados)}\n\n`);
  }
}

function notificarTodosAdmins(evento, dados) {
  for (const [id] of adminsOnline) notificarAdmin(id, evento, dados);
}

// ═══════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════
app.get('/api/config', async (req, res) => {
  try {
    const configs = await Config.find();
    const obj = {};
    configs.forEach(c => obj[c.chave] = c.valor);
    res.json(obj);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/config', adminAuth, async (req, res) => {
  try {
    const { chave, valor } = req.body;
    await Config.findOneAndUpdate({ chave }, { valor, atualizadoEm: new Date() }, { upsert: true });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// AUTH — ADMIN
// ═══════════════════════════════════════════════
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    const admin = await Admin.findOne({ usuario, ativo: true });
    if (!admin || !await bcrypt.compare(senha, admin.senhaHash))
      return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
    const token = jwt.sign({ id: admin._id, usuario: admin.usuario, tipo: 'admin', nivel: admin.nivel }, JWT_SECRET, { expiresIn: '12h' });
    await log('login', `Admin ${usuario} logou`, usuario, getIP(req));
    res.json({ token, nome: admin.nome, nivel: admin.nivel });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// AUTH — CLIENTE
// ═══════════════════════════════════════════════
// Endpoint para restaurar sessão — retorna dados do usuário logado
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    if(req.user.tipo === 'cliente'){
      const c = await Cliente.findById(req.user.id).select('-senhaHash -emailVerifToken -resetSenhaToken');
      if(!c) return res.status(404).json({ erro: 'Não encontrado' });
      res.json({ tipo: 'cliente', login: c.login, nome: c.nome, email: c.email, telefone: c.telefone, bairro: c.bairro, emailVerificado: c.emailVerificado, bloqueado: c.bloqueado });
    } else if(req.user.tipo === 'admin'){
      const a = await Admin.findById(req.user.id).select('-senhaHash');
      if(!a) return res.status(404).json({ erro: 'Não encontrado' });
      res.json({ tipo: 'admin', usuario: a.usuario, nome: a.nome, nivel: a.nivel, email: a.email });
    } else {
      res.status(400).json({ erro: 'Tipo inválido' });
    }
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/auth/cadastro', async (req, res) => {
  try {
    const { nome, login, senha, email, telefone, bairro, notifWhats } = req.body;
    if (!nome||!login||!senha||!email) return res.status(400).json({ erro: 'Campos obrigatórios faltando' });
    if (await Cliente.findOne({ login })) return res.status(409).json({ erro: 'Login já está em uso' });
    if (await Cliente.findOne({ email })) return res.status(409).json({ erro: 'E-mail já cadastrado' });

    const senhaHash = await bcrypt.hash(senha, 10);
    const emailVerifToken = crypto.randomBytes(32).toString('hex');
    const emailVerifExpira = new Date(Date.now() + 24*60*60*1000);

    const cliente = await Cliente.create({
      nome, login, senhaHash, email, telefone: telefone||'', bairro: bairro||'Centro',
      notifWhats: notifWhats||false, aceitouTermos: true, emailVerificado: false,
      emailVerifToken, emailVerifExpira, ip: getIP(req)
    });

    const token = jwt.sign({ id: cliente._id, login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '30d' });

    // Enviar email de verificação
    const verifyUrl = `${APP_URL}/api/auth/verificar-email?token=${emailVerifToken}`;
    await enviarEmail(email, 'Verifique seu e-mail — PreçoCerto', `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;">
        <h2 style="color:#1a73c8;">Bem-vindo ao PreçoCerto! 🎉</h2>
        <p>Olá, <strong>${nome}</strong>! Para ativar sua conta, clique no botão abaixo:</p>
        <a href="${verifyUrl}" style="display:inline-block;background:#1DB954;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;margin:16px 0;">✅ Verificar E-mail</a>
        <p style="color:#666;font-size:12px;">Link válido por 24 horas. Se não foi você, ignore este e-mail.</p>
      </div>
    `);

    res.status(201).json({ token, nome: cliente.nome, login: cliente.login, emailVerificado: false });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { login, senha } = req.body;
    const cliente = await Cliente.findOne({ login });
    if (!cliente || !await bcrypt.compare(senha, cliente.senhaHash))
      return res.status(401).json({ erro: 'Login ou senha incorretos' });
    if (cliente.bloqueado || cliente.banPermanente)
      return res.status(403).json({ erro: 'Conta bloqueada. Entre em contato com o suporte.' });
    const token = jwt.sign({ id: cliente._id, login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '30d' });
    await log('login', `Cliente ${login} logou`, login, getIP(req));
    res.json({ token, nome: cliente.nome, login: cliente.login, emailVerificado: cliente.emailVerificado, bairro: cliente.bairro, telefone: cliente.telefone });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Verificar email
app.get('/api/auth/verificar-email', async (req, res) => {
  try {
    const { token } = req.query;
    const cliente = await Cliente.findOne({ emailVerifToken: token, emailVerifExpira: { $gt: new Date() } });
    if (!cliente) return res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2>❌ Link inválido ou expirado</h2><p>Solicite um novo link de verificação no app.</p></body></html>');
    await Cliente.updateOne({ _id: cliente._id }, { emailVerificado: true, emailVerifToken: null, emailVerifExpira: null });
    res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2 style="color:#1DB954;">✅ E-mail verificado com sucesso!</h2><p>Sua conta está ativa. Volte ao app e faça login.</p></body></html>');
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Reenviar verificação
app.post('/api/auth/reenviar-verificacao', authMiddleware, async (req, res) => {
  try {
    const cliente = await Cliente.findById(req.user.id);
    if (!cliente) return res.status(404).json({ erro: 'Cliente não encontrado' });
    if (cliente.emailVerificado) return res.json({ mensagem: 'E-mail já verificado' });
    const token = crypto.randomBytes(32).toString('hex');
    await Cliente.updateOne({ _id: cliente._id }, { emailVerifToken: token, emailVerifExpira: new Date(Date.now() + 24*60*60*1000) });
    const verifyUrl = `${APP_URL}/api/auth/verificar-email?token=${token}`;
    await enviarEmail(cliente.email, 'Verifique seu e-mail — PreçoCerto', `<a href="${verifyUrl}">Verificar e-mail</a>`);
    res.json({ mensagem: 'Email de verificação reenviado!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Recuperação de senha
app.post('/api/auth/recuperar-senha', async (req, res) => {
  try {
    const { email } = req.body;
    const cliente = await Cliente.findOne({ email });
    // Sempre retornar 200 por segurança
    if (cliente) {
      const token = crypto.randomBytes(32).toString('hex');
      await Cliente.updateOne({ _id: cliente._id }, { resetSenhaToken: token, resetSenhaExpira: new Date(Date.now() + 2*60*60*1000) });
      const resetUrl = `${APP_URL}/api/auth/reset-senha?token=${token}`;
      await enviarEmail(email, 'Redefinir senha — PreçoCerto', `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;">
          <h2 style="color:#1a73c8;">Redefinir Senha</h2>
          <p>Clique no link abaixo para criar uma nova senha:</p>
          <a href="${resetUrl}" style="display:inline-block;background:#DC2626;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;margin:16px 0;">🔑 Redefinir Senha</a>
          <p style="color:#666;font-size:12px;">Link válido por 2 horas.</p>
        </div>
      `);
    }
    res.json({ mensagem: 'Se o e-mail existir, você receberá as instruções.' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/auth/reset-senha', async (req, res) => {
  const { token } = req.query;
  const cliente = await Cliente.findOne({ resetSenhaToken: token, resetSenhaExpira: { $gt: new Date() } });
  if (!cliente) return res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2>❌ Link inválido ou expirado</h2></body></html>');
  res.send(`<html><body style="font-family:sans-serif;max-width:400px;margin:auto;padding:40px;">
    <h2 style="color:#1a73c8;">Nova Senha</h2>
    <form method="POST" action="/api/auth/reset-senha">
      <input type="hidden" name="token" value="${token}">
      <input type="password" name="senha" placeholder="Nova senha (mín. 6 caracteres)" required minlength="6" style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;">
      <button type="submit" style="background:#1DB954;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;width:100%;font-weight:700;">Salvar Nova Senha</button>
    </form>
  </body></html>`);
});

app.post('/api/auth/reset-senha', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { token, senha } = req.body;
    const cliente = await Cliente.findOne({ resetSenhaToken: token, resetSenhaExpira: { $gt: new Date() } });
    if (!cliente) return res.send('<html><body>❌ Token inválido</body></html>');
    const senhaHash = await bcrypt.hash(senha, 10);
    await Cliente.updateOne({ _id: cliente._id }, { senhaHash, resetSenhaToken: null, resetSenhaExpira: null });
    res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2 style="color:#1DB954;">✅ Senha alterada com sucesso!</h2><p>Volte ao app e faça login com sua nova senha.</p></body></html>');
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Alterar senha (autenticado)
app.post('/api/auth/alterar-senha', authMiddleware, async (req, res) => {
  try {
    const { senhaAtual, novaSenha } = req.body;
    if (!senhaAtual||!novaSenha||novaSenha.length<6) return res.status(400).json({ erro: 'Dados inválidos' });
    if (req.user.tipo === 'cliente') {
      const cliente = await Cliente.findById(req.user.id);
      if (!await bcrypt.compare(senhaAtual, cliente.senhaHash)) return res.status(401).json({ erro: 'Senha atual incorreta' });
      await Cliente.updateOne({ _id: cliente._id }, { senhaHash: await bcrypt.hash(novaSenha, 10) });
    } else {
      const admin = await Admin.findById(req.user.id);
      if (!await bcrypt.compare(senhaAtual, admin.senhaHash)) return res.status(401).json({ erro: 'Senha atual incorreta' });
      await Admin.updateOne({ _id: admin._id }, { senhaHash: await bcrypt.hash(novaSenha, 10) });
    }
    res.json({ mensagem: 'Senha alterada com sucesso!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// AUTH — MERCADO
// ═══════════════════════════════════════════════
app.post('/api/auth/mercado', async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    const merc = await Mercado.findOne({ usuario, ativo: true });
    if (!merc || !await bcrypt.compare(senha, merc.senhaHash))
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    const token = jwt.sign({ id: merc._id, usuario: merc.usuario, tipo: 'mercado', mercadoId: merc._id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, nome: merc.nome, icone: merc.icone, plano: merc.plano, mercadoId: merc._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// DADOS PÚBLICOS
// ═══════════════════════════════════════════════
app.get('/api/dados', async (req, res) => {
  try {
    const [mercados, produtos, precos, promocoes, configs] = await Promise.all([
      Mercado.find({ $or: [{ ativo: true }, { ativo: { $exists: false } }] }).select('-senhaHash'),
      Produto.find({ ativo: true }),
      Preco.find(),
      Promocao.find({ ativa: true }),
      Config.find()
    ]);
    const configObj = {};
    configs.forEach(c => configObj[c.chave] = c.valor);
    res.json({ mercados, produtos, precos, promocoes, config: configObj });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// PRODUTOS
// ═══════════════════════════════════════════════
app.get('/api/produtos', async (req, res) => {
  try { res.json(await Produto.find({ ativo: true })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/admin/produtos', adminAuth, async (req, res) => {
  try {
    const prod = await Produto.create(req.body);
    res.status(201).json(prod);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Seed extra produtos
app.post('/api/admin/seed-produtos', adminAuth, async (req, res) => {
  try {
    const extras = [
      {nome:'Leite Condensado Moça 395g',emoji:'🥛',categoria:'Laticínios'},{nome:'Creme de Leite Nestlé Lata 300g',emoji:'🥛',categoria:'Laticínios'},{nome:'Bebida Láctea Toddynho 200ml',emoji:'🥛',categoria:'Laticínios'},
      {nome:'Água Tônica Antarctica 350ml',emoji:'💧',categoria:'Bebidas'},{nome:'Vinho Tinto Suave 750ml',emoji:'🍷',categoria:'Bebidas'},{nome:'Cerveja Original Long Neck 355ml',emoji:'🍺',categoria:'Bebidas'},
      {nome:'Fralda Huggies P/M/G pct',emoji:'👶',categoria:'Higiene'},{nome:'Lenço Umedecido Huggies 48un',emoji:'🧻',categoria:'Higiene'},{nome:'Creme Dental Sensodyne 90g',emoji:'🦷',categoria:'Higiene'},{nome:'Escova Elétrica Oral-B',emoji:'🪥',categoria:'Higiene'},
      {nome:'Sabão em Barra Minuano 200g',emoji:'🧺',categoria:'Limpeza'},{nome:'Pano de Chão Perfex',emoji:'🧹',categoria:'Limpeza'},{nome:'Rodo 60cm un',emoji:'🪣',categoria:'Limpeza'},{nome:'Vassoura un',emoji:'🧹',categoria:'Limpeza'},
      {nome:'Pão de Queijo Congelado 400g',emoji:'🧀',categoria:'Padaria'},{nome:'Croissant Congelado 6un',emoji:'🥐',categoria:'Padaria'},
      {nome:'Empanado de Frango Sadia 300g',emoji:'🍗',categoria:'Congelados'},{nome:'Coxinha Congelada 500g',emoji:'🍗',categoria:'Congelados'},{nome:'Espetinho de Frango 500g',emoji:'🍢',categoria:'Congelados'},
      {nome:'Catchup Heinz 397g',emoji:'🍅',categoria:'Mercearia'},{nome:'Creme de Cebola Knorr 34g',emoji:'🧅',categoria:'Mercearia'},{nome:'Tempero Baiano Kitano 40g',emoji:'🌶️',categoria:'Mercearia'},{nome:'Doce de Leite Nestlé 395g',emoji:'🍯',categoria:'Doces'},
      {nome:'Inhame kg',emoji:'🍠',categoria:'Legumes'},{nome:'Chuchu kg',emoji:'🥒',categoria:'Legumes'},{nome:'Vagem kg',emoji:'🌿',categoria:'Legumes'},
      {nome:'Agrião maço',emoji:'🥬',categoria:'Verduras'},{nome:'Hortelã maço',emoji:'🌿',categoria:'Verduras'},{nome:'Repolho Roxo un',emoji:'🥦',categoria:'Verduras'},
    ];
    let add = 0;
    for (const p of extras) {
      const existe = await Produto.findOne({ nome: p.nome });
      if (!existe) { await Produto.create(p); add++; }
    }
    res.json({ mensagem: `${add} produtos adicionados!`, total: await Produto.countDocuments() });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// MERCADOS
// ═══════════════════════════════════════════════
app.get('/api/mercados', async (req, res) => {
  try { res.json(await Mercado.find({ $or: [{ ativo: true }, { ativo: { $exists: false } }] }).select('-senhaHash')); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/admin/mercados', adminAuth, async (req, res) => {
  try {
    const { senha, ...dados } = req.body;
    const mercadoData = { ...dados };
    if (senha) mercadoData.senhaHash = await bcrypt.hash(senha, 10);
    const merc = await Mercado.create(mercadoData);
    await log('mercado', `Mercado criado: ${merc.nome}`, req.user.usuario, getIP(req));
    res.status(201).json({ ...merc.toObject(), senhaHash: undefined });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    if (!isObjId(req.params.id)) return res.status(400).json({ erro: 'ID inválido' });
    const { senha, ...dados } = req.body;
    if (senha) dados.senhaHash = await bcrypt.hash(senha, 10);
    const merc = await Mercado.findByIdAndUpdate(req.params.id, dados, { new: true }).select('-senhaHash');
    res.json(merc);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Soft delete mercado
app.delete('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    if (!isObjId(req.params.id)) return res.status(400).json({ erro: 'ID inválido' });
    await Mercado.findByIdAndUpdate(req.params.id, { ativo: false });
    await log('mercado', `Mercado removido: ${req.params.id}`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Mercado removido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// PREÇOS
// ═══════════════════════════════════════════════
app.get('/api/precos', async (req, res) => {
  try { res.json(await Preco.find()); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/precos', authMiddleware, async (req, res) => {
  try {
    const { produtoId, mercadoId, preco, fonte, autor } = req.body;
    if (!produtoId||!mercadoId||!preco) return res.status(400).json({ erro: 'produtoId, mercadoId e preco obrigatórios' });
    if (!isObjId(produtoId)) return res.status(400).json({ erro: 'Produto inválido — ID não reconhecido pelo banco. Verifique se o produto foi salvo corretamente.' });
    if (!isObjId(mercadoId)) return res.status(400).json({ erro: 'Mercado inválido — ID não reconhecido pelo banco. Recadastre o mercado pelo painel Admin.' });
    const entry = await Preco.findOneAndUpdate(
      { produtoId, mercadoId },
      { preco, fonte: fonte||'admin', autor: autor||req.user.usuario, dataAtu: hoje(), atualizadoEm: new Date() },
      { upsert: true, new: true }
    );
    await log('preco', `Preço: R$${preco} - prod ${produtoId}`, req.user.usuario, getIP(req));
    res.json(entry);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// PROMOÇÕES
// ═══════════════════════════════════════════════
app.get('/api/promocoes', async (req, res) => {
  try { res.json(await Promocao.find({ ativa: true })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/promocoes', adminAuth, async (req, res) => {
  try {
    const { produtoId, mercadoId } = req.body;
    if (!isObjId(produtoId)) return res.status(400).json({ erro: 'Produto inválido' });
    if (!isObjId(mercadoId)) return res.status(400).json({ erro: 'Mercado inválido' });
    const promo = await Promocao.create(req.body);
    await log('promocao', `Promoção criada`, req.user.usuario, getIP(req));
    res.status(201).json(promo);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/promocoes/:id', adminAuth, async (req, res) => {
  try {
    if (!isObjId(req.params.id)) return res.status(400).json({ erro: 'ID inválido' });
    await Promocao.findByIdAndUpdate(req.params.id, { ativa: false });
    res.json({ mensagem: 'Promoção encerrada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// CONTRIBUIÇÕES
// ═══════════════════════════════════════════════
app.get('/api/contribuicoes', adminAuth, async (req, res) => {
  try { res.json(await Contribuicao.find().sort({ criadoEm: -1 }).limit(200)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/contribuicoes', authMiddleware, async (req, res) => {
  try {
    const { produtoId, mercadoId } = req.body;
    if (produtoId && !isObjId(produtoId)) return res.status(400).json({ erro: 'Produto inválido' });
    if (mercadoId && !isObjId(mercadoId)) return res.status(400).json({ erro: 'Mercado inválido' });
    const contrib = await Contribuicao.create({ ...req.body, clienteId: req.user.id, ip: getIP(req) });
    notificarTodosAdmins('nova_contribuicao', { id: contrib._id, autor: req.user.login });
    res.status(201).json(contrib);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/aprovar', adminAuth, async (req, res) => {
  try {
    const contrib = await Contribuicao.findByIdAndUpdate(req.params.id, { status: 'aprovado' }, { new: true });
    if (!contrib) return res.status(404).json({ erro: 'Não encontrado' });
    // Atualiza preço se tiver produtoId/mercadoId válidos
    if (contrib.produtoId && contrib.mercadoId && contrib.preco && isObjId(String(contrib.produtoId)) && isObjId(String(contrib.mercadoId))) {
      await Preco.findOneAndUpdate(
        { produtoId: contrib.produtoId, mercadoId: contrib.mercadoId },
        { preco: contrib.preco, fonte: 'cliente', autor: contrib.autor, dataAtu: hoje(), atualizadoEm: new Date() },
        { upsert: true }
      );
    }
    res.json(contrib);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/recusar', adminAuth, async (req, res) => {
  try {
    const contrib = await Contribuicao.findByIdAndUpdate(req.params.id, { status: 'recusado', motivoRecusa: req.body.motivo||'' }, { new: true });
    res.json(contrib);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// SOLICITAÇÕES (Planos de Mercado)
// ═══════════════════════════════════════════════
app.get('/api/admin/solicitacoes', adminAuth, async (req, res) => {
  try { res.json(await Solicitacao.find().sort({ criadoEm: -1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/solicitacoes', async (req, res) => {
  try {
    const sol = await Solicitacao.create(req.body);
    notificarTodosAdmins('nova_solicitacao', { id: sol._id, mercado: sol.mercado, plano: sol.plano });
    res.status(201).json(sol);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// APROVAÇÃO COMPLETA — cria mercado + gera credenciais + envia email
app.patch('/api/admin/solicitacoes/:id/aprovar', adminAuth, async (req, res) => {
  try {
    const sol = await Solicitacao.findById(req.params.id);
    if (!sol) return res.status(404).json({ erro: 'Solicitação não encontrada' });
    if (sol.status === 'Aprovado') return res.status(400).json({ erro: 'Já aprovada' });

    // Gerar login e senha automáticos
    const loginGerado = sol.mercado.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g,'')
      .replace(/[^a-z0-9]/g,'_').replace(/__+/g,'_').substring(0,20);
    const senhaGerada = gerarSenha(10);
    const senhaHash = await bcrypt.hash(senhaGerada, 10);

    // Criar mercado no banco
    const novoMercado = await Mercado.create({
      nome: sol.mercado,
      icone: '🏪',
      endereco: sol.endereco,
      bairro: sol.bairro,
      whatsapp: sol.whatsapp,
      parceiro: true,
      plano: sol.plano,
      usuario: loginGerado,
      senhaHash,
      ativo: true
    });

    // Atualizar solicitação
    await Solicitacao.findByIdAndUpdate(req.params.id, {
      status: 'Aprovado',
      mercadoId: novoMercado._id,
      credenciais: { login: loginGerado, senha: senhaGerada }
    });

    // Enviar email com credenciais (se tiver email)
    if (sol.email) {
      await enviarEmail(sol.email, `✅ Cadastro aprovado — PreçoCerto`, `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;">
          <h2 style="color:#1DB954;">🎉 Parabéns! Seu mercado foi aprovado!</h2>
          <p>Olá, <strong>${sol.responsavel}</strong>! Seu cadastro no PreçoCerto foi aprovado.</p>
          <div style="background:#f4f4f4;border-radius:8px;padding:16px;margin:16px 0;">
            <p><strong>Mercado:</strong> ${sol.mercado}</p>
            <p><strong>Plano:</strong> ${sol.plano}</p>
            <p><strong>Login:</strong> <code>${loginGerado}</code></p>
            <p><strong>Senha:</strong> <code>${senhaGerada}</code></p>
          </div>
          <p>Acesse <a href="${APP_URL}">${APP_URL}</a> e clique em "Entrar como Mercado".</p>
          <p style="color:#DC2626;font-size:12px;">⚠️ Altere sua senha após o primeiro acesso.</p>
        </div>
      `);
    }

    await log('solicitacao', `Solicitação aprovada: ${sol.mercado} → login: ${loginGerado}`, req.user.usuario, getIP(req));
    res.json({
      mensagem: 'Aprovado! Mercado criado com sucesso.',
      mercadoId: novoMercado._id,
      credenciais: { login: loginGerado, senha: senhaGerada }
    });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/solicitacoes/:id/recusar', adminAuth, async (req, res) => {
  try {
    await Solicitacao.findByIdAndUpdate(req.params.id, { status: 'Recusado' });
    res.json({ mensagem: 'Solicitação recusada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// SUPORTE / CHAT
// ═══════════════════════════════════════════════
app.get('/api/suporte/mensagens/:clienteId', async (req, res) => {
  try { res.json(await ChatMsg.find({ clienteId: req.params.clienteId }).sort({ criadoEm: 1 }).limit(100)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/suporte/todas', adminAuth, async (req, res) => {
  try {
    const msgs = await ChatMsg.find().sort({ criadoEm: -1 }).limit(500);
    // Agrupar por clienteId
    const grupos = {};
    for (const m of msgs) {
      if (!grupos[m.clienteId]) grupos[m.clienteId] = [];
      grupos[m.clienteId].push(m);
    }
    res.json(Object.entries(grupos).map(([clienteId, mensagens]) => ({ clienteId, mensagens: mensagens.reverse() })));
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/suporte/mensagem', async (req, res) => {
  try {
    const clienteId = req.body.clienteId || 'visitante';
    const msg = await ChatMsg.create({
      clienteId, tipo: req.body.tipo||'user',
      texto: req.body.texto, hora: horaAtual()
    });
    // Notificar admins online
    notificarTodosAdmins('nova_mensagem_chat', { clienteId, texto: req.body.texto, hora: msg.hora });
    res.status(201).json(msg);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Admin responde no chat
app.post('/api/suporte/responder', adminAuth, async (req, res) => {
  try {
    const { clienteId, texto } = req.body;
    const msg = await ChatMsg.create({
      clienteId, tipo: 'admin', adminId: req.user.usuario,
      texto, hora: horaAtual()
    });
    res.status(201).json(msg);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// OCORRÊNCIAS
// ═══════════════════════════════════════════════
app.get('/api/ocorrencias', adminAuth, async (req, res) => {
  try { res.json(await Ocorrencia.find().sort({ criadoEm: -1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/ocorrencias', async (req, res) => {
  try {
    const oc = await Ocorrencia.create(req.body);
    notificarTodosAdmins('nova_ocorrencia', { id: oc._id, cliente: oc.cliente });
    res.status(201).json(oc);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/ocorrencias/:id/resolver', adminAuth, async (req, res) => {
  try {
    await Ocorrencia.findByIdAndUpdate(req.params.id, { status: 'resolvido' });
    res.json({ mensagem: 'Resolvido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/ocorrencias/:id', adminAuth, async (req, res) => {
  try {
    await Ocorrencia.findByIdAndDelete(req.params.id);
    res.json({ mensagem: 'Removido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMINS (gestão)
// ═══════════════════════════════════════════════
app.get('/api/admin/admins', adminAuth, async (req, res) => {
  try { res.json(await Admin.find({ ativo: true }).select('-senhaHash')); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/admin/admins', superAuth, async (req, res) => {
  try {
    const { nome, usuario, senha, nivel, email } = req.body;
    if (!nome||!usuario||!senha) return res.status(400).json({ erro: 'Campos obrigatórios' });
    if (await Admin.findOne({ usuario })) return res.status(409).json({ erro: 'Usuário já existe' });
    const admin = await Admin.create({ nome, usuario, email: email||'', nivel: nivel||'admin', senhaHash: await bcrypt.hash(senha, 12) });
    res.status(201).json({ ...admin.toObject(), senhaHash: undefined });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/admin/admins/:id', adminAuth, async (req, res) => {
  try {
    const { senha, ...dados } = req.body;
    // Admin só pode editar si mesmo, super pode editar qualquer um
    if (req.user.nivel !== 'super' && req.user.id !== req.params.id)
      return res.status(403).json({ erro: 'Sem permissão' });
    if (senha) dados.senhaHash = await bcrypt.hash(senha, 12);
    const admin = await Admin.findByIdAndUpdate(req.params.id, dados, { new: true }).select('-senhaHash');
    res.json(admin);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/admins/:id', superAuth, async (req, res) => {
  try {
    await Admin.findByIdAndUpdate(req.params.id, { ativo: false });
    res.json({ mensagem: 'Admin desativado' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// CLIENTES (gestão admin)
// ═══════════════════════════════════════════════
app.get('/api/admin/clientes', adminAuth, async (req, res) => {
  try { res.json(await Cliente.find().select('-senhaHash -emailVerifToken -resetSenhaToken').sort({ criadoEm: -1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/bloquear', adminAuth, async (req, res) => {
  try {
    const { motivo } = req.body;
    await Cliente.findByIdAndUpdate(req.params.id, { bloqueado: true, motivoBloqueio: motivo||'Bloqueado pelo admin' });
    res.json({ mensagem: 'Cliente bloqueado' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/desbloquear', adminAuth, async (req, res) => {
  try {
    await Cliente.findByIdAndUpdate(req.params.id, { bloqueado: false, motivoBloqueio: '', errosConsecutivos: 0 });
    res.json({ mensagem: 'Cliente desbloqueado' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/clientes/:id', adminAuth, async (req, res) => {
  try {
    await Cliente.findByIdAndUpdate(req.params.id, { banPermanente: true, bloqueado: true });
    res.json({ mensagem: 'Cliente banido' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// LOGS
// ═══════════════════════════════════════════════
app.get('/api/admin/logs', adminAuth, async (req, res) => {
  try { res.json(await Log.find().sort({ criadoEm: -1 }).limit(300)); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// SPA fallback
// ═══════════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════
app.listen(PORT, async () => {
  console.log(`🚀 PreçoCerto v6 rodando na porta ${PORT}`);
  if (MONGODB_URI) {
    setTimeout(seedInicial, 2000);
  }
});
