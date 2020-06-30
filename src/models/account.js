module.exports = (sequelize, DataTypes) => {

  const Account = sequelize.define('Account', {
    email : {
      type: DataTypes.STRING,
      allowNULL: false,
    },
    password : {
      type: DataTypes.STRING,
      allowNULL: false,
    },
  });

  Account.prototype.toJSON = function() {
    const values = {...this.get()};
    delete values.password;
    return values;
  };

  return Account;
}