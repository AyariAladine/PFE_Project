export default  () => ({
  database: {
    connectionString: process.env.MONGO_URL,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn:  process.env.JWT_EXPIRES_IN || '1h',
  },

});