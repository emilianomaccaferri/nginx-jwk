const express = require("express");
const app = express();

app.get('/', (req, res) => {
  res.json({
    message: "hello, valid jwt holder!"
  });
})

app.listen(3000);
console.log("listening");
