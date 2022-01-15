//Package to keep the sensitive data hidden...
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose"; 
import findOrCreate from "mongoose-findorcreate";

// Used t add cookies and sessions...
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";

// OAuth using Gooogle...
import GoogleStrategy from "passport-google-oauth20";
GoogleStrategy.Strategy;

const app = express();
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

//Initialize Session for cookies and sessions part...
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}));

// Initialize the passport...
app.use(passport.initialize());
app.use(passport.session());

// Connection to the DB...
mongoose.connect("mongodb+srv://secretsadmin:secrets_admin@cluster0.xb8wu.mongodb.net/userDB?retryWrites=true&w=majority");

//Schema for user DB...
const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Mongoose model...
const User = mongoose.model("users",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user,done){
    done(null,user.id);
});

passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});

// Google OAuth...
passport.use(new GoogleStrategy({
        clientID:process.env.CLIENT_ID,
        clientSecret:process.env.CLIENT_SECRET,
        callbackURL:"https://serene-hollows-97579.herokuapp.com/auth/google/secrets",
        userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken,refreshToken,profile,cb){
        User.findOrCreate({googleId:profile.id},function(err,user){
            return cb(err,user);
        });
    }
));


app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",passport.authenticate("google",{scope:["profile"]}));

app.get("/auth/google/secrets",
    passport.authenticate("google",{failureRedirect:"/login"}),
    function(req,res){
        res.redirect("/secrets");
    }
);

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}},function(err,foundUsers){
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets",{usersWithSecrets:foundUsers});
            }
        }
    });
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",function(req,res){
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

// let port = process.env.PORT;
// if (port == null || port == "") {
//   port = 3000;
// }

// app.listen(port,function(req,res){
//     console.log("Server has started successfully!!");
// });
app.listen(process.env.PORT || 3000, function(){
    console.log("OK");
});