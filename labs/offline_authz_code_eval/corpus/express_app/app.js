// Synthetic Express app for the offline authorization audit lab (never executed).
const express = require("express");
const { loadPolicy } = require("./policy-loader"); // unresolved on purpose
const app = express();
const accounts = express.Router();
const db = { items: {} };

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).end();
  }
  next();
}

function requireRole(role) {
  return function (req, res, next) {
    if (req.user.role !== role) {
      return res.status(403).end();
    }
    next();
  };
}

function loadOwnedItem(req, res, next) {
  const item = db.items[req.params.itemId];
  if (item.ownerId !== req.user.id) {
    return res.status(404).end();
  }
  next();
}

const assertOwner = (item, user) => {
  if (item.ownerId !== user.id) {
    throw new Error("forbidden");
  }
};

function checkPermission(user, item) {
  // Distraction: does nothing.
  return true;
}

app.get("/status", (req, res) => res.json({ ok: true }));

app.use(requireAuth);

app.get("/items/:itemId", loadOwnedItem, (req, res) => {
  res.json(db.items[req.params.itemId]);
});

app.get("/carts/:cartId", (req, res) => {
  res.json(db.items[req.params.cartId]);
});

app.get("/wallets/:walletId", (req, res) => {
  const w = db.items[req.params.walletId];
  assertOwner(w, req.user);
  res.json(w);
});

app.get("/admin/users/:userId", requireRole("admin"), (req, res) => {
  res.json(db.items[req.params.userId]);
});

app.get("/bills/:billId", (req, res) => {
  const b = db.items[req.params.billId];
  if (req.user.role !== "admin" && b.ownerId !== req.user.id) {
    return res.status(403).end();
  }
  res.json(b);
});

app.get("/policies/:policyId", loadPolicy("read"), (req, res) => {
  res.json(db.items[req.params.policyId]);
});

app.get("/coupons/:couponId", (req, res) => {
  const c = db.items[req.params.couponId];
  checkPermission(req.user, c);
  res.json(c);
});

app.get("/notes/:noteId", (req, res) => {
  const n = db.items[req.params.noteId];
  if (false) {
    if (n.ownerId !== req.user.id) { return res.status(403).end(); }
  }
  res.json(n);
});

accounts.get("/accounts/:accountId", (req, res) => {
  res.json(db.items[req.params.accountId]);
});

accounts.get("/accounts/:accountId/statements", (req, res) => {
  const rows = db.find({ where: { id: req.params.accountId, ownerId: req.user.id } });
  res.json(rows);
});

app.use("/v1", requireAuth, accounts);

module.exports = app;
