// Importing the Express framework
const express = require('express');
// Importing Mongoose
const mongoose = require('mongoose');
// Importing Session, flash and bcrypt
const session = require('express-session');
const flash = require('express-flash');
const bcrypt = require('bcrypt');

// Instantiating the Express app
const app = express();

// Setting the port
const PORT = 8080

// Connecting mongoose to the MongoDB
mongoose.connect('mongodb://localhost/dojoSecrets', {useNewUrlParser: true, useUnifiedTopology: true})

let Schema = mongoose.Schema;

// Create Schema and models
const UserSchema = new mongoose.Schema({
   email:{type: String, required: [true, 'Email is required'], match: [/^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/, "email entered is not of a valid form"]},
   first_name:{type: String, required:[true, 'A first name is required'], minlength:[2, 'First name must be at least 2 characters long']},
   last_name:{type: String, required:[true, 'A last name is required'], minlength:[2, 'Last name must be at least 2 characters long']},
   password:{type: String, required:[true, 'A password is required'], minlength: [8, 'Your password must be at least 8 characters long']},
   birthday:{type: Date, required:[true, 'You must enter your birthdate']},
   secrets: [{type: Schema.Types.ObjectId, ref:'Secret'}]
}, {timestamps: true})
const SecretSchema = mongoose.Schema({
    _user: {type: Schema.Types.ObjectId, ref: 'User'},
    content: {type: String, required: [true, "You must enter a secret"], minlength: [5, "Your secret must be at least 5 characters long."]}
},{timestamps: true})


// Create Object of Models
const User = mongoose.model('User', UserSchema)
const Secret = mongoose.model('Secret', SecretSchema)


// Setting the static directoy for express
app.use(express.static(__dirname + '/static'));
// Setting Express app to accept POST requests
app.use( express.urlencoded({extended: true}) );
// Setting up session for the app
app.set( 'trust proxy', 1 );
app.use( session({
    saveUnitialized: true,
    resave: 'true',
    secret: 'verysecret',
    cookie: {maxAge: 60000}
}) );
// Enabling flash messages 
app.use( flash() );

// Setting the view engine and directory for views
app.set( 'view engine', 'ejs' );
app.set( 'views', __dirname + '/views' );

// **ROUTES**
app.get('/', (req, res) => {
    res.render('index')
});
app.post('/register', (req, res) => {
    User.findOne({email:req.body.email}, (err,user) => {
        if(user){
            req.flash('reg', "That email is already in use.")
            return res.redirect('/')
        }
        else {
            if(req.body.password != req.body.passwordConfirm){
                req.flash('reg', "Passwords do not match")
                return res.redirect('/')
            }
        }
        bcrypt.hash(req.body.password, 10)
            .then(hashed_password => {
                const char = req.body.password.search(/[a-z]/);
                const num = req.body.password.search(/[0-9]/);
                const upperChar = req.body.password.search(/[A-Z]/);
                const length = req.body.password.length;
                if(char<0 || num<0 || upperChar<0){
                    req.flash('reg', "Password requires at least one uppercase letter and one number")
                    hashed_password = req.body.password;
                    req.session.errors = 1;
                }
                if(length < 8){
                    hashed_password = req.body.password;
                }
                newUser = new User({first_name: req.body.first_name, last_name: req.body.last_name, email: req.body.email, birthday: req.body.birthday, password: hashed_password})
                newUser.validate((err) => {
                    if(err){
                        for(let key in err.errors){
                            req.flash('reg', err.errors[key].message);
                        }
                        res.redirect('/')
                    }
                    else if(req.session.errors){
                        console.log(req.session.errors);
                        res.redirect('/');
                    }
                    else {
                        newUser.save(err => {
                            req.session.user_id = newUser._id;
                            req.session.first_name = newUser.first_name;
                            req.session.email = newUser.email;
                            req.session.user_id = newUser._id;
                            res.redirect('/secrets')
                        });
                    }
                });
            })
            .catch(err => res.redirect('/'))
    })
});
app.post('/login', (req, res) => {
    User.findOne({email: req.body.email}, (err,user) => {
        if(user){
            bcrypt.compare(req.body.password, user.password)
                .then(req.session.email = user.email, req.session.first_name = user.first_name, req.session.user_id = user._id, res.redirect('/secrets'))
                .catch(err => {res.json(err)})
        }
        else {
            req.flash('reg', "There is no user with those credentials.")
            res.redirect('/')
        }
    })    
});
app.post('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/')
});
app.get('/secrets', (req, res) => {
    Secret.find({})
        .populate('user')
        .exec((err,secrets) => {
            if(err){res.json(err)}
            else {res.render('secrets', {user:req.session, secrets:secrets})}
        })
    
});
app.post('/secret', (req, res) => {
    console.log(req.session);
    let user_id = req.session.user_id;
    User.findOne({_id: user_id}, (err,user) => {
        let newSecret = new Secret({content: req.body.content});
        newSecret._user = user_id;
        newSecret.content = req.body.secret;
        newSecret.save((err) => {
            if (err) {
                console.log(err);
            }
            else {
                User.update({_id:user_id}, {$push: {'secrets': newSecret}},(err) => {
                    if (err) {
                        console.log(err);
                    } else {
                        res.redirect('/secrets')
                    }
                });
            }
        })
    })
});
app.post('/secret/:id', (req, res) => {
    console.log(req.params.id);
    Secret.findByIdAndDelete({_id: req.params.id})
        .then(deletedSecret => res.redirect('/secrets'))
        .catch(err => res.json(err))
});
// Setting the app to listen on specified port
 app.listen(PORT, () => console.log("listening on port: ", PORT) );