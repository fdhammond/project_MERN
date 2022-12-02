import User from "../models/User.js";
import generateId from "../helpers/generateId.js";
import generateJWT from "../helpers/generateJWT.js";

const register = async (req, res) => {
  // Avoid duplicated register
  const { email } = req.body;
  const userExist = await User.findOne({ email });

  if (userExist) {
    const error = new Error("Already registered user");
    return res.status(400).json({ msg: error.message });
  }

  try {
    const user = new User(req.body);
    user.token = generateId();
    const storedUser = await user.save(); // permission for object, manipulate and store it.
    res.json(storedUser);
  } catch (error) {
    console.log(error);
  }
};

const authenticate = async (req, res) => {
  const { email, password } = req.body;

  //Test if user exist
  const user = await User.findOne({ email });

  if (!user) {
    //check if email exist in db
    const error = new Error("User does not exist");
    return res.status(404).json({ msg: error.message });
  }

  //Test if user is confirmed
  if (!user.confirmed) {
    //check if email exist in db
    const error = new Error("Account has not been confirmed");
    return res.status(403).json({ msg: error.message });
  }

  //Test password confirmation
  if (await user.checkPassword(password)) {
    /*se reestructura en un objeto para que traiga menos datos.
    queda mas prolijo asi el codigo solo va a traer los 3.*/
    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      token: generateJWT(user._id),
    });
  } else {
    const error = new Error("Incorrect Password");
    return res.status(403).json({ msg: error.message });
  }
};

const confirm = async (req, res) => {
  const { token } = req.params; //leemos la url
  //buscamos usuarios que ponen cualquier cosa en la url
  const confirmUser = await User.findOne({ token });
  //si no existe, token no valido
  if (!confirmUser) {
    const error = new Error("Invalid token");
    return res.status(403).json({ msg: error.message });
  }
  /* si existe, confirmamos el usuario,
eliminamos el token por que es de un solo uso */
  try {
    confirmUser.confirmed = true;
    /*token de un solo uso eliminamos el token
    la confirmacion va a ser por url mail por ende es 1 solo uso*/
    confirmUser.token = "";
    //almacenamos en la db
    await confirmUser.save(); //almacena el usuario con los cambios en la db
    //y le decimos que se confirmo correctamente
    res.json({ msg: "User confirmed successfully" });
  } catch (error) {
    console.log(error);
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  //Test if user exist
  const user = await User.findOne({ email });

  if (!user) {
    //check if email exist in db
    const error = new Error("User does not exist");
    return res.status(404).json({ msg: error.message });
  }

  try {
    user.token = generateId();
    await user.save();
    res.json({ msg: "Email has been sent with instructions" });
  } catch (error) {
    console.log(error);
  }
};

const checkToken = async (req, res) => {
  const { token } = req.params;
  const validToken = await User.findOne({ token });

  if (validToken) {
    res.json({ msg: "Valid token, user already exist" });
  } else {
    const error = new Error("Invalid token");
    return res.status(404).json({ msg: error.message });
  }
};

const newPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const user = await User.findOne({ token });

  if (user) {
    /*userSchema.pre("save") en el modelo comprobaba antes de almacenarlo
    si estaba hasheado, pero como no lo esta genera un nuevo salt y lo
    vuelve a hashear con el nuevo password*/
    user.password = password;
    user.token = ""; //borramos el token por que queda en el historial, peligroso
    try {
      await user.save();
      res.json({ msg: "Password has been changed successfully" });
    } catch (error) {
      console.log(error);
    }
  } else {
    const error = new Error("Invalid token");
    return res.status(404).json({ msg: error.message });
  }
};

export {
  register,
  authenticate,
  confirm,
  forgotPassword,
  checkToken,
  newPassword,
};
