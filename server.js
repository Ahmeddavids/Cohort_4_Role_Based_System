require('./config/dbConfig');
const express = require('express');
const router = require('./router/userRouter');
const PORT = process.env.PORT || 5050;
const app = express();

app.use(express.json());
app.use('/api/v1/user', router)

app.listen(PORT, () => {
    console.log(`Server is listening to PORT: ${PORT}`);
})