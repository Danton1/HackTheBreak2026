const { exec } = require('child_process');

function runDemo(userInput, userId) {
  const sql = "SELECT * FROM users WHERE id = " + userId;
  db.query(sql);

  document.getElementById('app').innerHTML = userInput;

  exec("ls " + userInput);

  eval(userInput);

  const APIkey = "super-secret-password";

  return { sql, password };
}

module.exports = { runDemo };
