const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const cors = require("cors");
const xss = require("x-xss-protection");
const jwt = require("jsonwebtoken");
const secretKey = "JEAGER";
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use(xss());

app.listen(process.env.PORT || 3000, () => {
  console.log("started");
});

const role = [
  "Superadmin",
  "admin",
  "director",
  "head of engineering",
  "operator",
];

const user = [
  { username: "Superman", password: "Superstar", role_id: 0, nama: "Suerman" },
  {
    username: "Adminis",
    password: "Adiministrator",
    role_id: 1,
    nama: "ADmin is",
  },
  { username: "Direct", password: "Directors", role_id: 2, nama: "DIRECT" },
  {
    username: "Headof",
    password: "Headofeng",
    role_id: 3,
    nama: "Head OF ENgginer",
  },
  { username: "opera", password: "opperator", role_id: 4, nama: "Superman" },
];

let data = [
  { nama_barang: "Amplop", warna: "Merah" },
  { nama_barang: "Toples", warna: "Biru" },
  { nama_barang: "Kardus", warna: "Merah" },
];

const checkToken = (req, res, next) => {
  const headerSecret = req.headers["access-token"];
  if (!headerSecret) return res.json({ message: "Unauthorized", status: 503 });
  const bearerToken = headerSecret.split(" ");
  const token = bearerToken[1];
  return jwt.verify(token, secretKey, (err, decoded) => {
    if (err && err.name === "TokenExpiredError")
      return res.json("Token Expired");
    if (err && err.name === "JsonWebTokenError")
      return res.json("Invalid Token");
    req.role_id = decoded.role_id;
    next();
  });
};

const checkRole = (req, res, next) => {
  if (role[req.role_id] !== "Superadmin") {
    return res.json({ message: "Access Forbidden", status: 503 });
  } else {
    next();
  }
};

app.post("/login", function (req, res) {
  let username = req.body.username || "";
  let password = req.body.password || "";
  let checkedUser = user.find(
    (item) => item.username === username && password === item.password
  );
  if (!checkedUser) {
    return res.send({
      message: "Please correct the Username or Password ",
      status: 500,
    });
  } else {
    delete checkedUser.password;
    checkedUser.token = jwt.sign(
      {
        role_id: checkedUser.role_id,
      },
      secretKey,
      { expiresIn: "1h" }
    );
    return res.json({ message: "Success", status: 200, result: checkedUser });
  }
});

app.post("/create", checkToken, checkRole, function (req, res) {
  let nama_barang = req.body.nama_barang || req.query.nama_barang || "";
  let warna = req.body.nama_barang || req.query.nama_barang || "";
  if (nama_barang !== "" && warna !== "") {
    data.push({ warna, nama_barang });
    return res.json({
      status: 200,
      message: "Success",
      result: data[data.length - 1],
    });
  } else {
    return res.send({ message: "isi semua field", status: 500 });
  }
});
app.patch("/update/:id", checkToken, checkRole, function (req, res) {
  let nama_barang = req.body.nama_barang || req.query.nama_barang || "";
  let warna = req.body.nama_barang || req.query.nama_barang || "";
  let id = isNaN(Number(req.params.id)) ? "" : Number(req.params.id) || "";
  if (id !== "" && nama_barang !== "" && warna !== "") {
    data[id] = { warna, nama_barang };
    return res.json({
      status: 200,
      message: "Success",
      result: data[id],
    });
  } else {
    return res.send({ message: "isi semua field", status: 500 });
  }
});
app.delete("/delete/:id", checkToken, checkRole, function (req, res) {
  let id = req.params.id || "";
  if (id !== "") {
    data.splice(id, 1);
    return res.json({
      status: 200,
      message: "Success",
      result: "",
    });
  } else {
    return res.send({ message: "isi semua field", status: 500 });
  }
});
app.get("/get", checkToken, function (req, res) {
  return res.json({
    status: 200,
    message: "Success",
    result: data,
  });
});
