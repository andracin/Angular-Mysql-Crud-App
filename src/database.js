const mysql = require('mysql');
const {database} = require('./keys');
const { promisify} = require('util');

const pool = mysql.createPool(database);

pool.getConnection((err, connection) =>{
    if(err){
        if(err.code === 'PROTOCOL_CONNECTION_LOST'){
        console.error('LA CONECCION CON LA BASE DE DATOS HA SIDO CERRADA');
    }
    if(err.code === 'ER_CON_COUNT_ERROR') {
        console.error('LA BASE DE DATOS TIENE MUCHAS CONECCIONES')
    }
    if(err.code === 'ENCONNREFUSED'){
        console.error(' LA CONECCION A LA BASE DE DATOS HA SIDO RECHAZADA');
    }
}
if(connection) connection.release();
  console.log(' LA BASE DE DATOS ESTA CONECTADA');
  return;
});
 
// @ts-ignore
pool.query  =   promisify(pool.query);
module.exports = pool;