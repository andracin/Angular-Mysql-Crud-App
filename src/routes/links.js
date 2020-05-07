// @ts-nocheck
const express =  require('express');
const router = express.Router();
const pool = require('../database')
const {isLoggedIn , isNotLoggedIn}= require('../lib/auth');



router.get('/add', isLoggedIn,  (req , res) => {
    res.render('./links/add');
});

router.post('/add', isLoggedIn , async (req , res) => {
    const {title, url, descrition, user_id } = req.body;
    const newLink = {
        title,
        url,
        descrition,
        user_id
    };
    await pool.query('INSERT INTO links set ?', [newLink]);
    req.flash('success', 'Link Guardado Sactifactoriamente')
    //console.log(user_id);
    res.redirect('/links');
});

router.get('/',  async ( req, res) => {
    const user_id = req.user.id;
    //console.log(user_id);
    const links =  await pool.query('SELECT * FROM links WHERE user_id =?', user_id);
    res.render('./links/list',{links});
});

 
router.get('/delete/:id', isLoggedIn,  async (req, res) => {
    const {id} =  req.params;
    await pool.query('DELETE FROM links  WHERE ID = ?',  [id]);
    req.flash('success', 'Link Borrado Sactifactoriamente')
    res.redirect('/links');
});   
router.get('/edit/:id', isLoggedIn ,  async (req, res) => {
    const {id} =  req.params;
    const links = await pool.query('SELECT * FROM links WHERE id = ?', [id]);    
    res.render('./links/edit', {link: links[0]});
});   

router.post('/edit/:id', isLoggedIn, async (req, res) => {
    const {id} =  req.params;
    const {title, descrition, url}  = req.body;
    const newLink  = {
        title,
        url,
        descrition
    };
    await pool.query('UPDATE  links set ?  WHERE  id = ?', [newLink, id]);
    req.flash('success', 'Link Actualizado Sactifactoriamente')
    res.redirect('/links');
});

module.exports = router;
