/**
 * PreçoCerto — Backend Node.js
 * ==============================
 * Serve o app para:
 *   - Site (navegador)
 *   - App Android (WebView)
 *   - App iOS (WKWebView)
 *
 * Endpoints REST + autenticação segura com JWT
 *
 * Para rodar:
 *   npm install
 *   node server.js
 *
 * Porta padrão: 3000
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'precocerto_secret_key_mude_em_producao';

// ─────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false })); // desabilita CSP para servir o HTML inline
app.use(cors({ origin: '*' })); // em prod: limitar ao domínio do app
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos (o HTML do app)
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 200,
  message: { erro: 'Muitas requisições. Tente novamente em 15 minutos.' }
});
app.use(limiter);

// Rate limiting específico para login (anti-brute-force)
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutos
  max: 10,
  message: { erro: 'Muitas tentativas de login. Aguarde 10 minutos.' }
});

// ─────────────────────────────────────────
// BANCO DE DADOS IN-MEMORY (simula DB)
// Em produção: conectar ao MongoDB ou PostgreSQL
// ─────────────────────────────────────────
let db = {
  admins: [
    { id: 1, usuario: 'admin', senhaHash: bcrypt.hashSync('Deusdaminhavida4321', 10), nome: 'Administrador', nivel: 'super' }
  ],
  clientes: [
    { id: 1, nome: 'Teste', login: 'teste', senhaHash: bcrypt.hashSync('1234', 10), email: 'teste@precocerto.app', telefone: '(75) 99999-0000', bairro: 'Centro', bloqueado: false, emailVerificado: true, dataCadastro: new Date().toLocaleDateString('pt-BR'), errosConsecutivos: 0, totalContribuicoes: 0, banTemporario: null, banPermanente: false }
  ],
  mercados: [
    { id: 1, nome: 'Mercado São João', icone: '🏪', endereco: 'Rua Principal, 45', bairro: 'Centro', usuario: 'mercado_joao', senhaHash: bcrypt.hashSync('joao123', 10), lat: -13.0774, lng: -41.7082 },
    { id: 2, nome: 'Supermercado Piatã', icone: '🛒', endereco: 'Av. Getúlio Vargas, 120', bairro: 'Centro', usuario: 'super_piata', senhaHash: bcrypt.hashSync('piata123', 10), lat: -13.0781, lng: -41.7095 }
  ],
  contribuicoes: [],
  logs: [],
  suporteChats: []
};

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────
function registrarLog(tipo, descricao, usuario, ip) {
  db.logs.push({
    id: Date.now(),
    tipo,
    descricao,
    usuario: usuario || 'anon',
    ip: ip || '0.0.0.0',
    data: new Date().toLocaleString('pt-BR'),
    timestamp: Date.now()
  });
  // Limita logs em memória a 1000 entradas
  if (db.logs.length > 1000) db.logs = db.logs.slice(-1000);
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '0.0.0.0';
}

// Middleware de autenticação JWT
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });
    next();
  });
}

// ─────────────────────────────────────────
// ROTAS — HEALTH CHECK
// ─────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'PreçoCerto Backend', version: '1.0.0', timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────
// ROTAS — AUTENTICAÇÃO
// ─────────────────────────────────────────

// Login Admin
app.post('/api/auth/admin', loginLimiter, (req, res) => {
  const { usuario, senha } = req.body;
  const ip = getIP(req);
  const admin = db.admins.find(a => a.usuario === usuario);
  if (!admin || !bcrypt.compareSync(senha, admin.senhaHash)) {
    registrarLog('auth_fail', 'Tentativa de login admin falhou', usuario, ip);
    return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
  }
  const token = jwt.sign({ id: admin.id, usuario: admin.usuario, tipo: 'admin', nivel: admin.nivel }, JWT_SECRET, { expiresIn: '8h' });
  registrarLog('auth', 'Login admin bem-sucedido', usuario, ip);
  res.json({ token, nome: admin.nome, nivel: admin.nivel });
});

// Login Cliente
app.post('/api/auth/cliente', loginLimiter, (req, res) => {
  const { login, senha } = req.body;
  const ip = getIP(req);
  const cliente = db.clientes.find(c => c.login === login);
  if (!cliente || !bcrypt.compareSync(senha, cliente.senhaHash)) {
    registrarLog('auth_fail', 'Tentativa de login cliente falhou', login, ip);
    return res.status(401).json({ erro: 'Login ou senha incorretos' });
  }
  if (cliente.banPermanente) return res.status(403).json({ erro: 'Conta banida permanentemente' });
  if (cliente.banTemporario && new Date(cliente.banTemporario) > new Date()) {
    return res.status(403).json({ erro: `Conta banida temporariamente até ${cliente.banTemporario}` });
  }
  const token = jwt.sign({ id: cliente.id, login: cliente.login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '24h' });
  registrarLog('auth', 'Login cliente', login, ip);
  res.json({ token, nome: cliente.nome, bloqueado: cliente.bloqueado, emailVerificado: cliente.emailVerificado });
});

// Cadastro Cliente
app.post('/api/auth/cadastro', loginLimiter, async (req, res) => {
  const { nome, login, senha, email, telefone, bairro } = req.body;
  const ip = getIP(req);
  if (!nome || !login || !senha || !email) return res.status(400).json({ erro: 'Campos obrigatórios: nome, login, senha, email' });
  if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres' });
  if (db.clientes.find(c => c.login === login)) return res.status(400).json({ erro: 'Login já em uso' });
  if (db.clientes.find(c => c.email === email)) return res.status(400).json({ erro: 'E-mail já cadastrado' });
  const senhaHash = bcrypt.hashSync(senha, 10);
  const novoCliente = {
    id: Date.now(), nome, login, senhaHash, email, telefone: telefone || '', bairro: bairro || 'Centro',
    bloqueado: false, emailVerificado: false, dataCadastro: new Date().toLocaleDateString('pt-BR'),
    errosConsecutivos: 0, totalContribuicoes: 0, contribuicoesRejeitadas: 0,
    ip, banTemporario: null, banPermanente: false, aceitouTermos: true, dataAceiteTermos: new Date().toISOString()
  };
  db.clientes.push(novoCliente);
  registrarLog('cadastro', `Novo cliente cadastrado: ${login}`, login, ip);
  // Em produção: enviar e-mail de verificação aqui
  // await enviarEmailVerificacao(email, token_verificacao);
  const token = jwt.sign({ id: novoCliente.id, login, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '24h' });
  res.status(201).json({ token, nome, mensagem: 'Conta criada! Verifique seu e-mail.' });
});

// Login Mercado
app.post('/api/auth/mercado', loginLimiter, (req, res) => {
  const { usuario, senha } = req.body;
  const ip = getIP(req);
  const merc = db.mercados.find(m => m.usuario === usuario);
  if (!merc || !bcrypt.compareSync(senha, merc.senhaHash)) {
    registrarLog('auth_fail', 'Login mercado falhou', usuario, ip);
    return res.status(401).json({ erro: 'Credenciais incorretas' });
  }
  const token = jwt.sign({ id: merc.id, usuario: merc.usuario, tipo: 'mercado' }, JWT_SECRET, { expiresIn: '12h' });
  registrarLog('auth', 'Login mercado', usuario, ip);
  res.json({ token, nome: merc.nome, icone: merc.icone });
});

// ─────────────────────────────────────────
// ROTAS — PRODUTOS E PREÇOS (públicos)
// ─────────────────────────────────────────
app.get('/api/mercados', (req, res) => {
  // Remove dados sensíveis antes de retornar
  const seguros = db.mercados.map(({ senhaHash, ...m }) => m);
  res.json(seguros);
});

app.get('/api/logs', adminMiddleware, (req, res) => {
  res.json(db.logs.slice().reverse().slice(0, 200));
});

// ─────────────────────────────────────────
// ROTAS — CONTRIBUIÇÕES
// ─────────────────────────────────────────
app.post('/api/contribuicoes', authMiddleware, (req, res) => {
  if (req.user.tipo !== 'cliente') return res.status(403).json({ erro: 'Apenas clientes podem contribuir' });
  const cliente = db.clientes.find(c => c.id === req.user.id);
  if (!cliente) return res.status(404).json({ erro: 'Cliente não encontrado' });
  if (cliente.bloqueado) return res.status(403).json({ erro: 'Conta bloqueada para contribuições' });
  const { produtoId, mercadoId, preco, tipo, obs } = req.body;
  if (!produtoId || !mercadoId || !preco) return res.status(400).json({ erro: 'produtoId, mercadoId e preco são obrigatórios' });
  const contrib = { id: Date.now(), tipo: tipo || 'texto', produtoId, mercadoId, preco, autor: cliente.nome, clienteId: cliente.id, data: new Date().toLocaleDateString('pt-BR'), status: 'pendente', obs: obs || '', ip: getIP(req) };
  db.contribuicoes.push(contrib);
  registrarLog('contribuicao', `Nova contribuição: produto ${produtoId} no mercado ${mercadoId}`, cliente.login, getIP(req));
  res.status(201).json({ mensagem: 'Contribuição enviada! Aguarda aprovação.', id: contrib.id });
});

// ─────────────────────────────────────────
// ROTAS — ADMIN: GESTÃO DE CLIENTES
// ─────────────────────────────────────────
app.get('/api/admin/clientes', adminMiddleware, (req, res) => {
  const seguros = db.clientes.map(({ senhaHash, ...c }) => c);
  res.json(seguros);
});

app.patch('/api/admin/clientes/:id/bloquear', adminMiddleware, (req, res) => {
  const c = db.clientes.find(x => x.id === parseInt(req.params.id));
  if (!c) return res.status(404).json({ erro: 'Cliente não encontrado' });
  const { tipo, dias, motivo } = req.body; // tipo: 'temp' | 'permanente'
  if (tipo === 'temp' && dias) {
    const ate = new Date(); ate.setDate(ate.getDate() + parseInt(dias));
    c.bloqueado = true; c.banTemporario = ate.toLocaleDateString('pt-BR'); c.banPermanente = false;
    c.motivoBloqueio = `Ban temporário por ${dias} dias`;
  } else {
    c.bloqueado = true; c.banPermanente = true; c.banTemporario = null;
    c.motivoBloqueio = motivo || 'Bloqueio permanente pelo administrador';
  }
  registrarLog('admin', `Cliente ${c.login} bloqueado (${tipo})`, req.user.usuario, getIP(req));
  res.json({ mensagem: 'Cliente bloqueado', cliente: { id: c.id, nome: c.nome, bloqueado: c.bloqueado } });
});

app.patch('/api/admin/clientes/:id/desbloquear', adminMiddleware, (req, res) => {
  const c = db.clientes.find(x => x.id === parseInt(req.params.id));
  if (!c) return res.status(404).json({ erro: 'Cliente não encontrado' });
  c.bloqueado = false; c.banTemporario = null; c.banPermanente = false;
  c.motivoBloqueio = ''; c.errosConsecutivos = 0;
  registrarLog('admin', `Cliente ${c.login} desbloqueado`, req.user.usuario, getIP(req));
  res.json({ mensagem: 'Cliente desbloqueado' });
});

app.delete('/api/admin/clientes/:id', adminMiddleware, (req, res) => {
  const idx = db.clientes.findIndex(x => x.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ erro: 'Cliente não encontrado' });
  const nome = db.clientes[idx].nome;
  db.clientes.splice(idx, 1);
  registrarLog('admin', `Cliente ${nome} excluído`, req.user.usuario, getIP(req));
  res.json({ mensagem: 'Cliente excluído' });
});

// ─────────────────────────────────────────
// ROTAS — SUPORTE CHAT
// ─────────────────────────────────────────
app.get('/api/suporte/chats', adminMiddleware, (req, res) => {
  res.json(db.suporteChats);
});

app.post('/api/suporte/mensagem', authMiddleware, (req, res) => {
  const { texto } = req.body;
  if (!texto?.trim()) return res.status(400).json({ erro: 'Texto obrigatório' });
  const clienteId = req.user.login || req.user.usuario || 'visitante';
  let sessao = db.suporteChats.find(s => s.clienteId === clienteId);
  if (!sessao) { sessao = { id: Date.now(), clienteId, mensagens: [], aberto: true, data: new Date().toLocaleDateString('pt-BR') }; db.suporteChats.push(sessao); }
  const hora = new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  sessao.mensagens.push({ tipo: 'user', texto: texto.trim(), hora, timestamp: Date.now() });
  registrarLog('chat', 'Mensagem de suporte enviada', clienteId, getIP(req));
  res.status(201).json({ mensagem: 'Enviado', hora });
});

// ─────────────────────────────────────────
// FALLBACK — Serve o app HTML para rotas desconhecidas
// ─────────────────────────────────────────
app.get('*', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.json({ mensagem: 'PreçoCerto API rodando. Coloque o index.html na pasta /public/' });
  }
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════╗
  ║  🔍 PreçoCerto Backend             ║
  ║  Rodando em: http://localhost:${PORT}  ║
  ║  Ambiente: ${process.env.NODE_ENV || 'development'}              ║
  ╚════════════════════════════════════╝

  Endpoints disponíveis:
  POST   /api/auth/admin          → Login admin
  POST   /api/auth/cliente        → Login cliente
  POST   /api/auth/cadastro       → Cadastro cliente
  POST   /api/auth/mercado        → Login mercado
  GET    /api/mercados            → Lista mercados
  POST   /api/contribuicoes       → Enviar contribuição (auth)
  GET    /api/admin/clientes      → Listar clientes (admin)
  PATCH  /api/admin/clientes/:id/bloquear
  PATCH  /api/admin/clientes/:id/desbloquear
  DELETE /api/admin/clientes/:id
  GET    /api/logs                → Logs do sistema (admin)
  GET    /api/suporte/chats       → Chats de suporte (admin)
  POST   /api/suporte/mensagem    → Enviar mensagem suporte (auth)
  `);
});

module.exports = app;
