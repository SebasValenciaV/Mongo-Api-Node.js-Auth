require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

const app = express();

// Configuración de EJS y archivos estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de la sesión
app.use(session({
  secret: process.env.SESSION_SECRET || 'defaultSecretForDev',
  resave: false,
  saveUninitialized: false,
}));

// Inicialización de Passport
app.use(passport.initialize());
app.use(passport.session());

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => console.error("Error conectando a MongoDB:", err));

// Definición del esquema y modelo de Usuario
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Configuración de Passport con estrategia local
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: 'Usuario no encontrado' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: 'Contraseña incorrecta' });
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware para rutas protegidas
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// Rutas

// Página de inicio
app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// Página de login
app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error });
});

// Proceso de login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login?error=true',
}));

// Página de registro
app.get('/register', (req, res) => {
  res.render('register', { errors: [] });
});

// Proceso de registro
app.post('/register', async (req, res) => {
  const { username, password, password2 } = req.body;
  const errors = [];

  if (!username || !password || !password2) {
    errors.push({ msg: 'Ingresa todos los campos' });
  }
  if (password !== password2) {
    errors.push({ msg: 'Las contraseñas no coinciden' });
  }
  if (password.length < 6) {
    errors.push({ msg: 'La contraseña debe tener al menos 6 caracteres' });
  }
  if (errors.length > 0) {
    return res.render('register', { errors });
  }

  try {
    const userExist = await User.findOne({ username });
    if (userExist) {
      errors.push({ msg: 'El usuario ya existe' });
      return res.render('register', { errors });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    errors.push({ msg: 'Error al registrar el usuario' });
    res.render('register', { errors });
  }
});

// Dashboard (ruta protegida)
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Cerrar sesión
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) return next(err);
    res.redirect('/');
  });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
