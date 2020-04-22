const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const pool = require('../database');
const helpers = require('../lib/helpers')

passport.use('local.signin', new LocalStrategy({
    usernameField :'username',
    passwordField: 'password',
    passReqToCallback: true
},async (req, username,  password, done) =>{
    const rows =await  pool.query('SELECT  * FROM users WHERE username=? ', [username]);
    if (rows.length > 0) {
         const user= rows[0];
         const  validPassword = await helpers.matchPasword(password, user.password);
         if (validPassword) {
             done(null, user, req.flash('seccess','Bienvenido'+ user.username));
         }else {
             done(null, false, req.flash('message','Password Incorrecto'));
         }
    }else {
        return done(null, false, req.flash('message','EL usuario no existe'));
    }
}));

passport.use('local.signup', new LocalStrategy({
    usernameField : 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username,  password, done) =>{
    const {fullname} =  req.body;
    const newUser = {
        username,
        password,
        fullname

    };
    newUser.password = await helpers.encryptPassword(password);
    const result = await  pool.query('INSERT INTO users set ?', [newUser]);
    newUser.id = result.insertId;
    return done(null, newUser);
   

}));

 passport.serializeUser((user, done) => {
     done(null, user.id);

});

passport.deserializeUser( async (id ,done ) =>{
    const rows = await pool.query('SELECT * FROM users WHERE id = ? ', [id]);
    done(null, rows[0]);

})