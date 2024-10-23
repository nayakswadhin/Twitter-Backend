export async function createUser(req, res) {
  try {
    const db = req.app.get("db");
    const { name, email, dateOfBirth, password } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Name is Required !!" });
    }
    if (!email) {
      return res.status(400).json({ message: "Email is Required!!" });
    }
    if (!password) {
      return res.status(400).json({ message: "Password is Required!!" });
    }
    if (!dateOfBirth) {
      return res.status(400).json({ message: "Date Of Birth is Required!!" });
    }

    const existingUser = await db.collection("user").findOne({ email: email });
    if (existingUser) {
      return res.status(400).json({ message: "Email Id already exist." });
    }
    const newuser = await db
      .collection("user")
      .insertOne({ name, email, password });
    if (newuser.acknowledged) {
      const userId = newuser.insertedId.toString();
      return res
        .status(200)
        .json({ message: "user created sucessfully", userId: userId });
    }
    return res.status(400).json({ message: "User is Not able to create" });
  } catch (error) {
    return res.status(400).json({ error: error.toString() });
  }
}

export async function loginController(req, res) {
  try {
    const db = req.app.get("db");
    const { email, password } = req.body;
    const user = await db.collection("user").findOne({ email: email });

    if (user) {
      const userId = user._id.toString();
      const name = user.name;
      if (password == user.password) {
        return res.status(200).json({
          message: "Successfully Logged In",
          userId: userId,
          name: name,
        });
      }
      return res.status(404).json({ message: "Incorrect Password" });
    }
    return res.status(400).json({
      message: "User Not Found. Please SignIn with Different Email Id",
    });
  } catch (error) {
    return res.status(400).json({ error: error.toString() });
  }
}
