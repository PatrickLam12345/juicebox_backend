const jwt = require("jsonwebtoken");
const { getUserById } = require("../db");
async function requireUser(req, res, next) {
  const prefix = "Bearer ";
  const auth = req.header("Authorization");
  if (!auth) {
    return res.status(401).json({ error: "Unauthorized" });
  } else if (auth.startsWith(prefix)) {
    const token = auth.slice(prefix.length);
    try {
      const { id } = jwt.verify(token, process.env.JWT_SECRET);
      if (id) {
        const user = await getUserById(id);
        if (user) {
          req.user = user;
          next();
        } else {
          res.status(401).json({ error: "Unauthorized" });
        }
      } else {
        res.status(401).json({ error: "Unauthorized" });
      }
    } catch (error) {
      console.log(error);
    }
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
}
module.exports = {
  requireUser,
};
