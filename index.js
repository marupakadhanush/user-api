const express = require("express");
const path = require("path");
const cors = require('cors');
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, "courier.db");
let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401).send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", (error, payload) => {
      if (error) {
        response.status(401).send("Invalid JWT Token");
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};
app.get("/profile/", authenticateToken, async (request, response) => {
  const { username } = request;
  console.log("Fetching profile for:", username); // Log username being fetched

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const userDetails = await db.get(selectUserQuery, [username]);
  console.log("User Details:", userDetails); // Log user details fetched
  response.send(userDetails);
});

app.post("/users/", async (request, response) => {
  const { username, name, password, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);
  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO 
        user (username, name, password, location) 
      VALUES 
        (?, ?, ?, ?)`;
    const dbResponse = await db.run(createUserQuery, [username, name, hashedPassword, location]);
    const newUserId = dbResponse.lastID;
    response.send(`Created new user with ID ${newUserId}`);
  } else {
    response.status(400).send("User already exists");
  }
});

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);
  if (dbUser === undefined) {
    response.status(400).send("Invalid User");
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
      const payload = { username: username };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
      response.send({ jwtToken });
    } else {
      response.status(400).send("Invalid Password");
    }
  }
});

app.get("/teachers", async (request, response) => {
  try {
    const selectTeachersQuery = `SELECT * FROM teacher`;
    const teachers = await db.all(selectTeachersQuery);
    response.json(teachers);
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/teachers/:id", async (request, response) => {
  const { id } = request.params;
  
  try {
    const selectTeacherQuery = `SELECT * FROM teacher WHERE id = ?`;
    const teacher = await db.get(selectTeacherQuery, [id]);
    
    if (!teacher) {
      response.status(404).json({ error: "Teacher not found" });
    } else {
      response.json(teacher);
    }
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.delete("/teachers/:id", async (request, response) => {
  const { id } = request.params;
  
  try {
    const deleteTeacherQuery = `DELETE FROM teacher WHERE id = ?`;
    const dbResponse = await db.run(deleteTeacherQuery, [id]);
    
    if (dbResponse.changes === 0) {
      response.status(404).json({ error: "Teacher not found" });
    } else {
      response.json({ message: `Deleted teacher with ID ${id}` });
    }
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.put("/teachers/:id", async (request, response) => {
  const { id } = request.params;
  const { name, subject, gender } = request.body;

  try {
    const updateTeacherQuery = `
      UPDATE teacher 
      SET name = ?, subject = ?, gender = ? 
      WHERE id = ?`;
    
    const dbResponse = await db.run(updateTeacherQuery, [name, subject, gender, id]);
    if (dbResponse.changes === 1) {
      response.send(`Teacher with ID ${id} updated successfully`);
    } else {
      response.status(404).send("Teacher not found");
    }
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});