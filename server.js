/**
 * PreçoCerto — Backend Node.js + MongoDB Atlas
 * ═══════════════════════════════════════════════
 * Dados em tempo real compartilhados entre TODOS os dispositivos:
 *   - Site (navegador)
 *   - App Android
 *   - App iOS
 *
 * Para rodar localmente:
 *   npm install
 *   node server.js
 *
 * Variáveis de ambiente necessárias (.env ou Render Dashboard):
 *   MONGODB_URI  = mongodb+srv://usuario:senha@cluster.mongodb.net/precocerto
 *   JWT_SECRET   = sua_chave_secreta_aqui
 *   PORT         = 3000 (opcional)
 */

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const mongoose   = require('mongoose');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET   = process.env.JWT_SECRET   || 'precocerto_dev_secret';
const MONGODB_URI  = process.env.MONGODB_URI  || '';

// ⚠️ OBRIGATÓRIO no Render/Heroku — informa ao Express que está atrás de proxy
app.set('trust proxy', 1);

// ═══════════════════════════════════════════════
// CONEXÃO MONGODB
// ═══════════════════════════════════════════════
if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB Atlas conectado!'))
    .catch(e  => console.error('❌ Erro MongoDB:', e.message));
} else {
  console.warn('⚠️  MONGODB_URI não definida — rodando sem banco de dados persistente');
}

// ═══════════════════════════════════════════════
// SCHEMAS MONGOOSE
// ═══════════════════════════════════════════════

const AdminSchema = new mongoose.Schema({
  usuario:    { type: String, required: true, unique: true },
  senhaHash:  { type: String, required: true },
  nome:       { type: String, required: true },
  nivel:      { type: String, default: 'admin' },
  criadoEm:   { type: Date, default: Date.now }
});

const ClienteSchema = new mongoose.Schema({
  nome:                 { type: String, required: true },
  login:                { type: String, required: true, unique: true, lowercase: true },
  senhaHash:            { type: String, required: true },
  email:                { type: String, required: true, unique: true, lowercase: true },
  telefone:             { type: String, default: '' },
  bairro:               { type: String, default: 'Centro' },
  foto:                 { type: String, default: null },
  bloqueado:            { type: Boolean, default: false },
  banTemporario:        { type: String, default: null },
  banPermanente:        { type: Boolean, default: false },
  motivoBloqueio:       { type: String, default: '' },
  dataBloqueio:         { type: String, default: null },
  emailVerificado:      { type: Boolean, default: false },
  aceitouTermos:        { type: Boolean, default: false },
  dataAceiteTermos:     { type: Date, default: null },
  errosConsecutivos:    { type: Number, default: 0 },
  totalContribuicoes:   { type: Number, default: 0 },
  contribuicoesRejeitadas: { type: Number, default: 0 },
  ip:                   { type: String, default: '' },
  dataCadastro:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:             { type: Date, default: Date.now }
});

const MercadoSchema = new mongoose.Schema({
  nome:       { type: String, required: true },
  icone:      { type: String, default: '🏪' },
  endereco:   { type: String, default: '' },
  bairro:     { type: String, default: 'Centro' },
  parceiro:   { type: Boolean, default: false },
  plano:      { type: String, default: null },
  usuario:    { type: String, default: null },
  senhaHash:  { type: String, default: null },
  website:    { type: String, default: null },
  lat:        { type: Number, default: null },
  lng:        { type: Number, default: null },
  criadoEm:   { type: Date, default: Date.now }
});

const ProdutoSchema = new mongoose.Schema({
  nome:       { type: String, required: true },
  emoji:      { type: String, default: '📦' },
  categoria:  { type: String, default: 'Geral' },
  criadoEm:   { type: Date, default: Date.now }
});

const PrecoSchema = new mongoose.Schema({
  produtoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Produto', required: true },
  mercadoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  preco:      { type: Number, required: true },
  dataAtu:    { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  fonte:      { type: String, default: 'admin' }, // admin | mercado | cliente | app
  autor:      { type: String, default: 'Admin' },
  atualizadoEm: { type: Date, default: Date.now }
});

const PromocaoSchema = new mongoose.Schema({
  produtoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Produto', required: true },
  mercadoId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado', required: true },
  precoNormal:  { type: Number, required: true },
  precoPromo:   { type: Number, required: true },
  descricao:    { type: String, default: '' },
  validade:     { type: String, required: true },
  ativa:        { type: Boolean, default: true },
  criadoEm:     { type: Date, default: Date.now }
});

const ContribuicaoSchema = new mongoose.Schema({
  tipo:       { type: String, default: 'texto' }, // foto | texto | qr | report
  produtoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Produto' },
  mercadoId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Mercado' },
  preco:      { type: Number, default: null },
  autor:      { type: String, default: 'Anônimo' },
  clienteId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', default: null },
  status:     { type: String, default: 'pendente' }, // pendente | aprovado | recusado
  motivoRecusa: { type: String, default: '' },
  obs:        { type: String, default: '' },
  fotoUrl:    { type: String, default: null },
  ip:         { type: String, default: '' },
  data:       { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:   { type: Date, default: Date.now }
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
  texto:      { type: String, required: true },
  hora:       { type: String, required: true },
  lida:       { type: Boolean, default: false },
  criadoEm:   { type: Date, default: Date.now }
});

const ConfigSchema = new mongoose.Schema({
  chave:  { type: String, required: true, unique: true },
  valor:  { type: mongoose.Schema.Types.Mixed, required: true },
  atualizadoEm: { type: Date, default: Date.now }
});

const SolicitacaoSchema = new mongoose.Schema({
  mercado:      { type: String, required: true },
  responsavel:  { type: String, required: true },
  whatsapp:     { type: String, required: true },
  endereco:     { type: String, default: '' },
  bairro:       { type: String, default: '' },
  plano:        { type: String, required: true },
  status:       { type: String, default: 'Pendente' },
  data:         { type: String, default: () => new Date().toLocaleDateString('pt-BR') },
  criadoEm:     { type: Date, default: Date.now }
});

// Modelos
const Admin       = mongoose.model('Admin', AdminSchema);
const Cliente     = mongoose.model('Cliente', ClienteSchema);
const Mercado     = mongoose.model('Mercado', MercadoSchema);
const Produto     = mongoose.model('Produto', ProdutoSchema);
const Preco       = mongoose.model('Preco', PrecoSchema);
const Promocao    = mongoose.model('Promocao', PromocaoSchema);
const Contribuicao= mongoose.model('Contribuicao', ContribuicaoSchema);
const Log         = mongoose.model('Log', LogSchema);
const ChatMsg     = mongoose.model('ChatMsg', ChatMsgSchema);
const Config      = mongoose.model('Config', ConfigSchema);
const Solicitacao = mongoose.model('Solicitacao', SolicitacaoSchema);

// ═══════════════════════════════════════════════
// SEED — Dados iniciais (só roda se DB estiver vazio)
// ═══════════════════════════════════════════════
async function seedInicial() {
  try {
    // Admin padrão
    const admCount = await Admin.countDocuments();
    if (admCount === 0) {
      await Admin.create({
        usuario: 'admin',
        senhaHash: bcrypt.hashSync('Deusdaminhavida4321', 10),
        nome: 'Administrador',
        nivel: 'super'
      });
      console.log('✅ Admin padrão criado');
    }

    // Cliente teste
    const cliCount = await Cliente.countDocuments();
    if (cliCount === 0) {
      await Cliente.create({
        nome: 'Teste', login: 'teste',
        senhaHash: bcrypt.hashSync('1234', 10),
        email: 'teste@precocerto.app',
        telefone: '(75) 99999-0000', bairro: 'Centro',
        emailVerificado: true, aceitouTermos: true
      });
      console.log('✅ Cliente teste criado');
    }

    // Mercados
    const mercCount = await Mercado.countDocuments();
    if (mercCount === 0) {
      await Mercado.insertMany([
        { nome: 'Mercado São João', icone: '🏪', endereco: 'Rua Principal, 45', bairro: 'Centro', usuario: 'mercado_joao', senhaHash: bcrypt.hashSync('joao123', 10), lat: -13.0774, lng: -41.7082 },
        { nome: 'Supermercado Piatã', icone: '🛒', endereco: 'Av. Getúlio Vargas, 120', bairro: 'Centro', usuario: 'super_piata', senhaHash: bcrypt.hashSync('piata123', 10), lat: -13.0781, lng: -41.7095 },
        { nome: 'Mini Mercado da Praça', icone: '🏬', endereco: 'Praça da Matriz, 8', bairro: 'Centro', lat: -13.0769, lng: -41.7078 },
        { nome: 'Empório Rural', icone: '🌿', endereco: 'Estrada do Sertão, km 3', bairro: 'Zona Rural', lat: -13.0820, lng: -41.7130 }
      ]);
      console.log('✅ Mercados iniciais criados');
    }

    // Config padrão de planos
    const cfgCount = await Config.countDocuments();
    if (cfgCount === 0) {
      await Config.insertMany([
        { chave: 'cidade',    valor: 'Piatã' },
        { chave: 'estado',    valor: 'BA' },
        { chave: 'whatsapp',  valor: '5575999999999' },
        { chave: 'precos_planos', valor: { basico: 39.90, pro: 69.90, premium: 119.90 } }
      ]);
      console.log('✅ Configurações iniciais criadas');
    }

    console.log('✅ Seed completo!');
  } catch (e) {
    console.error('Erro no seed:', e.message);
  }
}

// Roda seed após conectar
mongoose.connection.once('open', seedInicial);

// ═══════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15*60*1000, max: 300 });
const loginLimiter = rateLimit({ windowMs: 10*60*1000, max: 15 });
app.use(limiter);

// ═══════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '0.0.0.0';
}

async function log(tipo, descricao, usuario, ip) {
  try { await Log.create({ tipo, descricao, usuario: usuario||'anon', ip: ip||'', data: new Date().toLocaleString('pt-BR') }); }
  catch(e) { /* silencioso */ }
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ erro: 'Token inválido ou expirado' }); }
}

function adminAuth(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });
    next();
  });
}

// ═══════════════════════════════════════════════
// ROTAS — HEALTH
// ═══════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'PreçoCerto', versao: '2.0.0', db: mongoose.connection.readyState === 1 ? 'conectado' : 'desconectado', timestamp: new Date().toISOString() });
});

// ═══════════════════════════════════════════════
// ROTAS — CONFIG (pública para o app carregar)
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
    await log('config', `Config atualizada: ${chave}`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Config atualizada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — AUTENTICAÇÃO
// ═══════════════════════════════════════════════

// Login Admin
app.post('/api/auth/admin', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    const ip = getIP(req);
    const admin = await Admin.findOne({ usuario });
    if (!admin || !bcrypt.compareSync(senha, admin.senhaHash)) {
      await log('auth_fail', 'Login admin falhou', usuario, ip);
      return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
    }
    const token = jwt.sign({ id: admin._id, usuario: admin.usuario, tipo: 'admin', nivel: admin.nivel }, JWT_SECRET, { expiresIn: '8h' });
    await log('auth', 'Login admin', usuario, ip);
    res.json({ token, nome: admin.nome, nivel: admin.nivel });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Login Cliente
app.post('/api/auth/cliente', loginLimiter, async (req, res) => {
  try {
    const { login, senha } = req.body;
    const ip = getIP(req);
    const cliente = await Cliente.findOne({ login: login.toLowerCase() });
    if (!cliente || !bcrypt.compareSync(senha, cliente.senhaHash)) {
      await log('auth_fail', 'Login cliente falhou', login, ip);
      return res.status(401).json({ erro: 'Login ou senha incorretos' });
    }
    if (cliente.banPermanente) return res.status(403).json({ erro: 'Conta banida permanentemente' });
    if (cliente.banTemporario && new Date(cliente.banTemporario) > new Date()) {
      return res.status(403).json({ erro: `Conta banida até ${cliente.banTemporario}` });
    }
    const token = jwt.sign({ id: cliente._id, login: cliente.login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '24h' });
    await log('auth', 'Login cliente', login, ip);
    res.json({ token, nome: cliente.nome, bloqueado: cliente.bloqueado, emailVerificado: cliente.emailVerificado, bairro: cliente.bairro });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Cadastro Cliente
app.post('/api/auth/cadastro', loginLimiter, async (req, res) => {
  try {
    const { nome, login, senha, email, telefone, bairro } = req.body;
    const ip = getIP(req);
    if (!nome||!login||!senha||!email) return res.status(400).json({ erro: 'Campos obrigatórios: nome, login, senha, email' });
    if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres' });
    if (await Cliente.findOne({ login: login.toLowerCase() })) return res.status(400).json({ erro: 'Login já em uso' });
    if (await Cliente.findOne({ email: email.toLowerCase() })) return res.status(400).json({ erro: 'E-mail já cadastrado' });
    const cliente = await Cliente.create({
      nome, login: login.toLowerCase(), senhaHash: bcrypt.hashSync(senha, 10),
      email: email.toLowerCase(), telefone: telefone||'', bairro: bairro||'Centro',
      ip, aceitouTermos: true, dataAceiteTermos: new Date()
    });
    const token = jwt.sign({ id: cliente._id, login: cliente.login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '24h' });
    await log('cadastro', `Novo cliente: ${login}`, login, ip);
    res.status(201).json({ token, nome, mensagem: 'Conta criada com sucesso!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Login Mercado
app.post('/api/auth/mercado', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    const ip = getIP(req);
    const merc = await Mercado.findOne({ usuario });
    if (!merc || !bcrypt.compareSync(senha, merc.senhaHash)) {
      await log('auth_fail', 'Login mercado falhou', usuario, ip);
      return res.status(401).json({ erro: 'Credenciais incorretas' });
    }
    const token = jwt.sign({ id: merc._id, usuario: merc.usuario, tipo: 'mercado' }, JWT_SECRET, { expiresIn: '12h' });
    await log('auth', 'Login mercado', usuario, ip);
    res.json({ token, nome: merc.nome, icone: merc.icone, mercadoId: merc._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — DADOS PÚBLICOS (app carrega ao abrir)
// ═══════════════════════════════════════════════
app.get('/api/mercados', async (req, res) => {
  try {
    const mercados = await Mercado.find().select('-senhaHash');
    res.json(mercados);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/produtos', async (req, res) => {
  try {
    const produtos = await Produto.find().sort({ categoria: 1, nome: 1 });
    res.json(produtos);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/precos', async (req, res) => {
  try {
    const precos = await Preco.find().populate('produtoId mercadoId');
    res.json(precos);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/promocoes', async (req, res) => {
  try {
    const promos = await Promocao.find({ ativa: true }).populate('produtoId mercadoId');
    res.json(promos);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — PREÇOS (admin/mercado podem atualizar)
// ═══════════════════════════════════════════════
app.post('/api/precos', authMiddleware, async (req, res) => {
  try {
    const { produtoId, mercadoId, preco, fonte, autor } = req.body;
    if (!produtoId||!mercadoId||!preco) return res.status(400).json({ erro: 'produtoId, mercadoId e preco obrigatórios' });
    const entry = await Preco.findOneAndUpdate(
      { produtoId, mercadoId },
      { preco, fonte: fonte||'admin', autor: autor||req.user.usuario, dataAtu: new Date().toLocaleDateString('pt-BR'), atualizadoEm: new Date() },
      { upsert: true, new: true }
    );
    await log('preco', `Preço atualizado: produto ${produtoId}`, req.user.usuario, getIP(req));
    res.json(entry);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — PROMOÇÕES
// ═══════════════════════════════════════════════
app.post('/api/promocoes', adminAuth, async (req, res) => {
  try {
    const promo = await Promocao.create(req.body);
    await log('promocao', 'Nova promoção criada', req.user.usuario, getIP(req));
    res.status(201).json(promo);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/promocoes/:id', adminAuth, async (req, res) => {
  try {
    await Promocao.findByIdAndUpdate(req.params.id, { ativa: false });
    res.json({ mensagem: 'Promoção encerrada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — CONTRIBUIÇÕES
// ═══════════════════════════════════════════════
app.get('/api/contribuicoes', adminAuth, async (req, res) => {
  try {
    const contribs = await Contribuicao.find({ status: 'pendente' }).sort({ criadoEm: -1 }).limit(100);
    res.json(contribs);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/contribuicoes', authMiddleware, async (req, res) => {
  try {
    if (req.user.tipo !== 'cliente') return res.status(403).json({ erro: 'Apenas clientes podem contribuir' });
    const cliente = await Cliente.findById(req.user.id);
    if (!cliente) return res.status(404).json({ erro: 'Cliente não encontrado' });
    if (cliente.bloqueado) return res.status(403).json({ erro: 'Conta bloqueada para contribuições' });
    const { produtoId, mercadoId, preco, tipo, obs } = req.body;
    if (!produtoId||!mercadoId||!preco) return res.status(400).json({ erro: 'produtoId, mercadoId e preco obrigatórios' });
    const contrib = await Contribuicao.create({ tipo: tipo||'texto', produtoId, mercadoId, preco, autor: cliente.nome, clienteId: cliente._id, obs: obs||'', ip: getIP(req) });
    await log('contribuicao', `Nova contribuição de ${cliente.login}`, cliente.login, getIP(req));
    res.status(201).json({ mensagem: 'Contribuição enviada! Aguarda aprovação.', id: contrib._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/aprovar', adminAuth, async (req, res) => {
  try {
    const contrib = await Contribuicao.findById(req.params.id);
    if (!contrib) return res.status(404).json({ erro: 'Contribuição não encontrada' });
    contrib.status = 'aprovado';
    await contrib.save();
    // Atualiza preço no banco
    await Preco.findOneAndUpdate(
      { produtoId: contrib.produtoId, mercadoId: contrib.mercadoId },
      { preco: contrib.preco, fonte: 'cliente', autor: contrib.autor, dataAtu: new Date().toLocaleDateString('pt-BR'), atualizadoEm: new Date() },
      { upsert: true }
    );
    // Reseta erros consecutivos do cliente
    if (contrib.clienteId) {
      await Cliente.findByIdAndUpdate(contrib.clienteId, { $set: { errosConsecutivos: 0 }, $inc: { totalContribuicoes: 1 } });
    }
    await log('admin', `Contribuição aprovada: ${contrib._id}`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Contribuição aprovada e preço publicado!' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/contribuicoes/:id/recusar', adminAuth, async (req, res) => {
  try {
    const { motivo } = req.body;
    const contrib = await Contribuicao.findByIdAndUpdate(req.params.id, { status: 'recusado', motivoRecusa: motivo||'Preço incorreto' }, { new: true });
    if (!contrib) return res.status(404).json({ erro: 'Contribuição não encontrada' });
    // Registra erro no cliente
    if (contrib.clienteId) {
      const cliente = await Cliente.findById(contrib.clienteId);
      if (cliente) {
        cliente.errosConsecutivos = (cliente.errosConsecutivos||0) + 1;
        cliente.contribuicoesRejeitadas = (cliente.contribuicoesRejeitadas||0) + 1;
        if (cliente.errosConsecutivos >= 3 && !cliente.bloqueado) {
          cliente.bloqueado = true;
          cliente.motivoBloqueio = `Bloqueio automático após 3 erros: ${motivo}`;
          cliente.dataBloqueio = new Date().toLocaleDateString('pt-BR');
        }
        await cliente.save();
      }
    }
    await log('admin', `Contribuição recusada: ${motivo}`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Contribuição recusada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — ADMIN: GESTÃO COMPLETA
// ═══════════════════════════════════════════════

// Clientes
app.get('/api/admin/clientes', adminAuth, async (req, res) => {
  try {
    const clientes = await Cliente.find().select('-senhaHash').sort({ criadoEm: -1 });
    res.json(clientes);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/bloquear', adminAuth, async (req, res) => {
  try {
    const { tipo, dias, motivo } = req.body;
    const update = { bloqueado: true, motivoBloqueio: motivo||'Bloqueio pelo admin', dataBloqueio: new Date().toLocaleDateString('pt-BR') };
    if (tipo === 'temp' && dias) {
      const ate = new Date(); ate.setDate(ate.getDate() + parseInt(dias));
      update.banTemporario = ate.toLocaleDateString('pt-BR');
      update.banPermanente = false;
      update.motivoBloqueio = `Ban temporário por ${dias} dias`;
    } else {
      update.banPermanente = true; update.banTemporario = null;
    }
    const c = await Cliente.findByIdAndUpdate(req.params.id, update, { new: true }).select('-senhaHash');
    await log('admin', `Cliente ${c?.login} bloqueado (${tipo||'permanente'})`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Cliente bloqueado', cliente: c });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.patch('/api/admin/clientes/:id/desbloquear', adminAuth, async (req, res) => {
  try {
    const c = await Cliente.findByIdAndUpdate(req.params.id, { bloqueado: false, banPermanente: false, banTemporario: null, motivoBloqueio: '', errosConsecutivos: 0 }, { new: true }).select('-senhaHash');
    await log('admin', `Cliente ${c?.login} desbloqueado`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Cliente desbloqueado', cliente: c });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/clientes/:id', adminAuth, async (req, res) => {
  try {
    const c = await Cliente.findByIdAndDelete(req.params.id);
    await log('admin', `Cliente ${c?.login} excluído`, req.user.usuario, getIP(req));
    res.json({ mensagem: 'Cliente excluído' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Mercados
app.post('/api/admin/mercados', adminAuth, async (req, res) => {
  try {
    const dados = { ...req.body };
    if (dados.senha) { dados.senhaHash = bcrypt.hashSync(dados.senha, 10); delete dados.senha; }
    const merc = await Mercado.create(dados);
    await log('admin', `Mercado criado: ${merc.nome}`, req.user.usuario, getIP(req));
    res.status(201).json(merc);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.put('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    const dados = { ...req.body };
    if (dados.senha) { dados.senhaHash = bcrypt.hashSync(dados.senha, 10); delete dados.senha; }
    const merc = await Mercado.findByIdAndUpdate(req.params.id, dados, { new: true }).select('-senhaHash');
    res.json(merc);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/mercados/:id', adminAuth, async (req, res) => {
  try {
    await Mercado.findByIdAndDelete(req.params.id);
    res.json({ mensagem: 'Mercado excluído' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Produtos
app.post('/api/admin/produtos', adminAuth, async (req, res) => {
  try {
    const prod = await Produto.create(req.body);
    res.status(201).json(prod);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Logs
app.get('/api/admin/logs', adminAuth, async (req, res) => {
  try {
    const logs = await Log.find().sort({ criadoEm: -1 }).limit(200);
    res.json(logs);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.delete('/api/admin/logs', adminAuth, async (req, res) => {
  try {
    await Log.deleteMany({});
    res.json({ mensagem: 'Logs limpos' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// Solicitações
app.get('/api/admin/solicitacoes', adminAuth, async (req, res) => {
  try { res.json(await Solicitacao.find().sort({ criadoEm: -1 })); }
  catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/solicitacoes', async (req, res) => {
  try {
    const sol = await Solicitacao.create(req.body);
    res.status(201).json({ mensagem: 'Solicitação enviada!', id: sol._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// ROTAS — SUPORTE CHAT
// ═══════════════════════════════════════════════
app.get('/api/suporte/chats', adminAuth, async (req, res) => {
  try {
    const msgs = await ChatMsg.find().sort({ criadoEm: -1 }).limit(500);
    // Agrupa por clienteId
    const grupos = {};
    msgs.reverse().forEach(m => {
      if (!grupos[m.clienteId]) grupos[m.clienteId] = { clienteId: m.clienteId, mensagens: [] };
      grupos[m.clienteId].mensagens.push(m);
    });
    res.json(Object.values(grupos));
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/suporte/mensagem', authMiddleware, async (req, res) => {
  try {
    const { texto } = req.body;
    if (!texto?.trim()) return res.status(400).json({ erro: 'Texto obrigatório' });
    const clienteId = req.user.login || req.user.usuario || 'visitante';
    const hora = new Date().toLocaleTimeString('pt-BR', { hour:'2-digit', minute:'2-digit' });
    const msg = await ChatMsg.create({ clienteId, tipo: 'user', texto: texto.trim(), hora });
    await log('chat', 'Mensagem de suporte', clienteId, getIP(req));
    res.status(201).json({ mensagem: 'Enviado', hora, id: msg._id });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/suporte/responder', adminAuth, async (req, res) => {
  try {
    const { clienteId, texto } = req.body;
    const hora = new Date().toLocaleTimeString('pt-BR', { hour:'2-digit', minute:'2-digit' });
    await ChatMsg.create({ clienteId, tipo: 'admin', texto: texto.trim(), hora });
    res.status(201).json({ mensagem: 'Resposta enviada' });
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

app.get('/api/suporte/mensagens/:clienteId', authMiddleware, async (req, res) => {
  try {
    const msgs = await ChatMsg.find({ clienteId: req.params.clienteId }).sort({ criadoEm: 1 });
    res.json(msgs);
  } catch(e) { res.status(500).json({ erro: e.message }); }
});

// ═══════════════════════════════════════════════
// FALLBACK
// ═══════════════════════════════════════════════
app.get('*', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'index.html');
  const fs = require('fs');
  if (fs.existsSync(htmlPath)) res.sendFile(htmlPath);
  else res.json({ app: 'PreçoCerto API v2.0', status: 'online', docs: '/api/health' });
});

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║  🔍 PreçoCerto Backend v2.0           ║
  ║  Porta: ${PORT}                           ║
  ║  DB:    ${MONGODB_URI ? 'MongoDB Atlas' : 'Sem banco configurado'}       ║
  ╚═══════════════════════════════════════╝
  `);
});

module.exports = app;
