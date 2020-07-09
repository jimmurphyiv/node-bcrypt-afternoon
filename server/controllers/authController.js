const bcrypt = require('bcryptjs');

module.exports = {

register: async (req, res) => {
    const {username, password, isAdmin} = req.body;
    const db = req.app.get('db');
    const result = await db.get_user([username]);
    const exsistingUser = result[0];
    if (exsistingUser){
        return res.status(409).send('Username is already Slaying');
    }
    const salt = bcrypt.genSaltSync(11);
    const hash = bcrypt.hashSync(password, salt);
    const registeredUser = await db.register_user([isAdmin, username, hash]);
    const user = registeredUser;
    req.session.user = {isAdmin: user.is_admin, username: user.username, id: user.id};
    return res.status (201).send(req.session.user);
},


login: async (req, res) => {
    const {username, password} = req.body;
    const foundUser = await req.app.get('db').get_user([username]);
    const user = foundUser[0];
    if (!user){
        return res.status(401).send('User not Slaying, Please register before Slaying');
    }
    const isAuthenticated = bcrypt.compareSync(password, user.hash);
    if (!isAuthenticated){
        return res.status(403).send('Password not Slaying');
    }
    req.session.user = { isAdmin: user.is_admin, id: user.id, username: user.username};
    return res.send(req.session.user);
    },

logout: (req, res) => {
    req.session.destroy();
    return res.sendStatus(200);
}
};
