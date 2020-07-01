module.exports = (sequelize, DataTypes) => {

  const Link = sequelize.define('Link', {
    label : {
      type: DataTypes.STRING,
      allowNULL: false,
    },
    url : {
      type: DataTypes.STRING,
      allowNULL: false,
    },
    image : {
      type: DataTypes.STRING,
      allowNULL: false,
    },
    isSocial : {
      type: DataTypes.BOOLEAN,
      allowNULL: false,
      default: 0,
    },
  });

  Link.associate = (models) => {
    Link.belongsTo(models.Account, {foreignKey: 'accountId'});
  };

  return Link;
}