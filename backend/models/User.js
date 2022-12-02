import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    },
    token: {
      type: String,
    },
    confirmed: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  //Revisa que el password no haya sido cambiado - hasheado lo hasheado
  //el middleware con next() hace que salte al otro directamente
  if (!this.isModified("password")) {
    next(); //no ejecutes lo siguiente sino que anda al otro middleware
  }
  //Se pasa el objeto del User con this
  const salt = await bcrypt.genSalt(10);
  //Genera el hash y lo guarda en el password por eso el this aca,
  //toma el primer parametro y el otro el salt es lo que lo transforma
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.checkPassword = async function (formPassword) {
  //toma el pw que el user escribio en el formulario
  return await bcrypt.compare(formPassword, this.password); //compare the password that the user is writing with the existing one.
};

const User = mongoose.model("User", userSchema);

export default User;
