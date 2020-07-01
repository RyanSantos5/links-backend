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

  Account.associate = (models) => {
    Account.hasMany(models.Link, {foreignKey: 'accountId'});
  }

  Account.prototype.toJSON = function() {
    const values = {...this.get()};
    delete values.password;
    return values;
  };

  return Account;
}