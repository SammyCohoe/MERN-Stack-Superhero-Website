const express = require("express");
const cors = require("cors");
const passport = require("passport")
const bcrypt = require("bcrypt")
const Storage = require('node-storage');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
const mongoose = require('mongoose');
const User = require('./model/model.js');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const secretKey = "secret";


const port = 8000;
const supeInfo = require('./superhero_info.json')
const supePowers = require('./superhero_powers.json')

app.use(cors());
app.use(express.json());
require('dotenv').config();

// Configure express-session
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

const mongoString = process.env.DATABASE_URL;

mongoose.connect(mongoString);
const database = mongoose.connection;

// function to decode jwt token
function decodeJwt(token) {
    // Split the token into its three parts: header, payload, and signature
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  
    // Decode each part from Base64
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64').toString());
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
  
    // The signature is not decoded in this example
  
    // Return the decoded header and payload
    return { header, payload };
}

// return if database is not connected
database.on('error', (error) => {
    console.log(error)
})

// return if database is connected
database.once('connected', () => {
    console.log('Database Connected');
})

//set middleware to do logging
app.use((req, res, next) => {
    console.log(`${req.method} request for ${req.url}`);
    next();
})

// print statement for port
app.listen(port, () => {
    console.log(`Server is running on port ${port}.`);
});

// create a new user 
app.post(`/api/open/createUser`, async (req, res) => {
    const { username, password, email, type, flag, lists } = req.body;

    const emailValidation = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailValidation.test(email)) {
        return res.status(409).send("Invalid Email");
    }

    if(!password){
        return res.status(409).send("Invalid Password");
    }

    if(!username){
        return res.status(409).send("Invalid Username");
    }


    try {
        // Check if the user already exists by username or email
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });

        if (existingUser) {
            if (existingUser.username === username) {
                return res.status(409).send(`A user with this username already exists.`);
            } else if (existingUser.email === email) {
                return res.status(409).send(`A user with this email already exists.`);
            }
        } else {
            // Hash the password before saving it
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Create a new user
            
            const newUser = new User({ username, password: hashedPassword, email, type: type || "nonAuthenticated", flag, lists });
            await newUser.save();
            res.status(200).send('User created successfully.');
        }
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Configure LocalStrategy for email and password authentication
passport.use(
    new LocalStrategy({ usernameField: 'email' }, async function verify(email, password, cb) {
      try {
        const user = await User.findOne({ email });
  
        if (!user) {
          return cb(null, false, { message: 'User does not exist.' });
        }
  
        if (user.flag === "disabled") {
          return cb(null, false, { message: 'Please contact the site administrator.' });
        }
  
        const passwordMatch = await bcrypt.compare(password, user.password);
  
        if (!passwordMatch) {
          return cb(null, false, { message: 'Incorrect password.' });
        }
  
        return cb(null, user, { message: 'Valid User' });
      } catch (error) {
        console.error(error);
        return cb(error);
      }
    })
);
  
// Serialize and deserialize user 
passport.serializeUser((user, done) => {
    done(null, user._id.toString());
});
  
passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
});
  
// Login endpoint using JWT
app.post('/api/open/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error' });
        }

        if (!user) {
            return res.status(401).json({ message: info.message || 'Unsuccessful login.' });
        }

        // Generate a JWT token with additional user information
        const token = jwt.sign(
            {
                userId: user._id,
                username: user.username,
                email: user.email,
                type: user.type,
                flag: user.flag
            },
            'secret',
            { expiresIn: '24h' }
        );

        console.log(decodeJwt(token));

        return res.status(200).json({ token, message: info.message || 'Successful login.' });
    })(req, res, next);
});

// endpoint to verify user email
app.get('/api/open/verifyEmail/:token' , async (req, res) => {
    const verifyToken = req.params.token;

    console.log(decodeJwt(verifyToken).payload.email);

    try{
        const validToken = jwt.verify(verifyToken, secretKey);
        const userEmail = decodeJwt(verifyToken).payload.email;

        const user = await User.findOne({ email: userEmail });

        if(user){
            console.log(user.type)
            if(user.type === "admin"){
                return;
            } 
            else{
                user.type = "authenticated";
                await user.save();
                console.log(user)
                res.json({message : `${userEmail}'s account is authenticated.`})
            }
            
        }else {
            res.status(404).send("User not found.")
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


/***********************************************************
 * EVERYTHING BELOW IS RELATED TO SUPERHERO FUNCTIONALITIES*
 ***********************************************************/

// return all information about a superhero given an ID
app.get('/api/supeInfo/:id', (req, res) => {
    console.log(`GET request for ${req.url}`);
    const supe = supeInfo.find(supe => supe.id === parseInt(req.params.id));
    if(supe){
        res.send(supe);
    }
    else {
        res.status(404).send(`Supe number ${req.params.id} was not found`);
    }
    
}) ;

// return all powers for a given superhero ID
app.get('/api/supePowers/:id', (req, res) => {
    console.log(`GET request for ${req.url}`);
    const supe = supeInfo.find(supe => supe.id === parseInt(req.params.id));
    const supeName = supe.name;
    const supePowersObject = supePowers.find(supe => supe.hero_names == supeName);
    var powersList = [];

    var powers = Object.entries(supePowersObject);
    for([key, value] of powers){
        if(value == "True"){
            powersList.push(key);
        }
    }

    if(supe){
        res.send(powersList);
    }
    else {
        res.status(404).send(`Supe number ${req.params.id} was not found`);
    }
});

// return all supes 
app.get('/api/supeInfo', (req, res) => {
    console.log(`GET request for ${req.url}`);
    res.send(supeInfo)
});

// return all supes and powers
app.get('/api/supePowers', (req, res) => {
    console.log(`GET request for ${req.url}`);
    res.send(supePowers)
});

// this code makes use of the levenshteinDistance algorithm to compare string lengths
// i did not come up with this and found it online and modified it 
function levenshteinDistance(str1, str2) {
    const m = str1.length;
    const n = str2.length;

    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) {
        for (let j = 0; j <= n; j++) {
            if (i === 0) {
                dp[i][j] = j;
            } else if (j === 0) {
                dp[i][j] = i;
            } else {
                dp[i][j] = Math.min(
                    dp[i - 1][j - 1] + (str1[i - 1] !== str2[j - 1] ? 1 : 0),
                    dp[i][j - 1] + 1,
                    dp[i - 1][j] + 1
                );
            }
        }
    }
    return dp[m][n];
}

function areSimilar(str1, str2) {
    return levenshteinDistance(str1, str2) <= 2;
}

// function to search for superheros
app.get('/api/supeInfo/:field/:pattern/:n?', (req, res) => {
    const field = req.params.field;
    const pattern = req.params.pattern.trim().toLowerCase(); // Convert to lowercase and remove whitespace
    var n = Number(req.params.n);

    const supeId = [];
    if (isNaN(n)) {
        n = Infinity;
    }

    if (!supeInfo[0].hasOwnProperty(field)) {
        res.status(400).send(`${field} not a valid field.`);
        return;
    }

    supeInfo.forEach((supe) => {
        if (supeId.length < n) {
            // Convert supe[field] to lowercase and remove whitespace for comparison
            const fieldValue = supe[field].trim().toLowerCase();

            if (areSimilar(fieldValue, pattern)) {
                supeId.push(supe.id);
            }
        }
    });

    console.log(`SupeId array: ${supeId}`);
    res.json(supeId);
});

/***********************************************************
 * EVERYTHING ABOVE IS RELATED TO SUPERHERO FUNCTIONALITIES*
 ***********************************************************/


app.get("/message", (req, res) => {
  res.json({ message: "Hello from server!" });
});


// add a new list with a list name 
app.post('/api/secure/addList', async (req, res) => {
    const { username, favList, description, ids } = req.body;

    console.log(username);
    console.log(favList);
    console.log(description);
    console.log(ids);

    try {
        // Find the user in the database based on the username
        const user = await User.findOne({ username });

        console.log('User:', user);

        if (!user) {
            res.status(404).send(`${username} not found.`);
        } else {
            console.log('User lists:', user.lists);

            user.lists = user.lists ?? {};

            // Check if the list already exists for the user
            if (!user.lists[favList]) {
                // If the list doesn't exist or was previously deleted, add it to the user's lists
                user.lists[favList] = {
                    description: description || "",
                    visibility: "private",
                    ids: ids,
                    reviews: {},
                    lastModified: new Date().toISOString(),
                    listCreator: username
                };

                // Update only the lists field
                await User.updateOne({ username }, { $set: { lists: user.lists } });

                console.log('User after save:', user);

                res.status(200).send(`${favList} list created for ${username}.`);
            } else {
                res.status(409).send(`${favList} list already exists for ${username}.`);
            }
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// add a review to a list
app.post(`/api/secure/lists/review`, async (req, res) => {
    const { username, reviewUsername, listName, rating, comment } = req.body;

    try {
        // Find the user in the database
        const user = await User.findOne({ username });

        if (!user) {
            res.status(404).send(`${username} not found.`);
            return;
        }

        // Generate a unique review ID
        const reviewId = uuidv4(); // Generate a unique review ID

        const reviewPath = `lists.${listName}.reviews`;

        // Get today's date and format it (e.g., 'YYYY-MM-DD')
        const today = new Date();
        const formattedDate = today.toISOString().split('T')[0];

        // Create the new review object
        const newReview = {
            [reviewUsername]: {
                rating: rating,
                comment: comment || "",
                visibility: "public",
                reviewId: reviewId,
                reviewDate: formattedDate,
            },
        };

        // Update the review fields 
        await User.updateOne(
            { username, [`lists.${listName}`]: { $exists: true } },
            {
                $set: {
                    [reviewPath]: newReview,
                },
            }
        );

        res.status(200).send(`Review added with ID: ${reviewId}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// change list name 
app.post('/api/secure/lists/newListName', async (req, res) => {
    const { username, listName, newListName } = req.body;

    try {
        // Find the user in the database
        const user = await User.findOne({ username });

        // Return error if the user isn't found
        if (!user) {
            res.status(404).send(`${username} not found.`);
            return;
        }

        // Check if the list exists
        if (user.lists && user.lists[listName]) {
            // Update the listName key using $rename
            await User.updateOne(
                { username, [`lists.${listName}`]: { $exists: true } },
                { $rename: { [`lists.${listName}`]: `lists.${newListName}` } }
            );

            // Update the lastModified field for the renamed list
            await User.updateOne(
                { username, [`lists.${newListName}`]: { $exists: true } },
                { $set: { [`lists.${newListName}.lastModified`]: new Date().toISOString() } }
            );

            res.status(200).send(`List updated to ${newListName}`);
        } else {
            res.status(404).send(`${listName} not found in the lists.`);
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// change list description
app.post(`/api/secure/lists/description`, async (req, res) => {
    const { username, listName, description } = req.body;

    try{
        // Find the user in the database 
        const user = await User.findOne({ username });

        // return error if the user isnt found
        if(!user){
            res.status(404).send(`${username} not found.`)
            return;
        }

        // Update the description and lastModified fields
        await User.updateOne(
            { username, [`lists.${listName}`]: { $exists: true } },
            {
                $set: {
                    [`lists.${listName}.description`]: description,
                    [`lists.${listName}.lastModified`]: new Date().toISOString()
                }
            }
        );
        res.status(200).send(`${listName}'s description now ${description}`);
        
    }
    catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

//set the ids on a list 
app.post(`/api/secure/lists/ids`, async (req, res) => {
    const { username, listName, ids } = req.body;

    console.log(ids)

    try{
        // Find the user in the database 
        const user = await User.findOne({ username });

        // return error if the user isnt found
        if(!user){
            res.status(404).send(`${username} not found.`)
        } else {
            console.log("Current list vis:" + user.lists[listName].visibility);

            user.lists[listName].ids = "ids";
            user.lists[listName].lastModified = new Date().toISOString();

            // Update the description and lastModified fields
        await User.updateOne(
            { username, [`lists.${listName}`]: { $exists: true } },
            {
                $set: {
                    [`lists.${listName}.ids`]: ids,
                    [`lists.${listName}.lastModified`]: new Date().toISOString()
                }
            }
        );

            res.status(200).send(`${listName}'s ids updated.`)
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

//set the visibility on a list 
app.post(`/api/secure/lists/visibility`, async (req, res) => {
    const { username, listName, visibility } = req.body;

    try{
        // Find the user in the database 
        const user = await User.findOne({ username });

        // return error if the user isnt found
        if(!user){
            res.status(404).send(`${username} not found.`)
        } else {
            console.log("Current list vis:" + user.lists[listName].visibility);

            user.lists[listName].visibility = "visibility";
            user.lists[listName].lastModified = new Date().toISOString();

            // Update the description and lastModified fields
        await User.updateOne(
            { username, [`lists.${listName}`]: { $exists: true } },
            {
                $set: {
                    [`lists.${listName}.visibility`]: visibility,
                    [`lists.${listName}.lastModified`]: new Date().toISOString()
                }
            }
        );

            res.status(200).send(`${listName}'s visibility now ${visibility}`)
        }
    }
    catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

//delete a list
app.delete('/api/secure/lists/delete', async (req, res) => {
    const { username, listName } = req.body;

    try {
        // Find the user in the database
        const user = await User.findOne({ username });

        // Return an error if the user isn't found
        if (!user) {
            res.status(404).send(`${username} not found.`);
        } else {
            // Check if the list exists
            if (user.lists && user.lists[listName]) {
                // Remove the list using $unset
                await User.updateOne(
                    { username },
                    { $unset: { [`lists.${listName}`]: 1 } }
                );

                res.status(200).send(`${listName} deleted successfully.`);
            } else {
                res.status(404).send(`${listName} not found in user's lists.`);
            }
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// get all lists for a given user
app.get('/api/secure/listData/all/:username?', async (req, res) => {
    try {
        const { username } = req.params;

        if(username === "none"){
            try {
                // Fetch all users from the database
                const allUsers = await User.find();
        
                // Extract lists from all users without list names
                const allLists = allUsers.reduce((acc, user) => {
                    if (user.lists && Object.keys(user.lists).length > 0) {
                        Object.entries(user.lists).forEach(([listName, listDetails]) => {
                            acc.push({ [listName]: { ...listDetails } });
                        });
                    }
                    return acc;
                }, []);
        
                // Sort the lists by lastModified date in descending order
                const sortedLists = allLists.sort((a, b) => new Date(b[Object.keys(b)[0]].lastModified) - new Date(a[Object.keys(a)[0]].lastModified));
        
                // Return the sorted lists as a response
                res.status(200).json(sortedLists);
                return;
            } catch (error) {
                console.error(error);
                res.status(500).send('Internal Server Error');
                return;
            }
        }

        // Fetch the user from the database
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(404).send(`${username} not found.`);
        }

        // Extract lists from the user
        const userLists = Object.entries(user.lists).map(([listName, listDetails]) => ({
            [listName]: { ...listDetails }
        }));

        // Sort the lists by lastModified date in descending order
        const sortedLists = userLists.sort((a, b) => new Date(b[Object.keys(b)[0]].lastModified) - new Date(a[Object.keys(a)[0]].lastModified));

        // Return the sorted lists as a response
        res.status(200).json(sortedLists);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// endpoint to change a user's password
app.post('/api/secure/changePassword', async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    try {
        // Fetch all users from the database
        const user = await User.findOne({ email: email });

        // check if previous password matches current password 
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        console.log(passwordMatch)
        console.log(oldPassword)
        console.log(newPassword)
        if(!passwordMatch){
            res.status(409).send('Wrong password.');
            return;
        }

        

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the user's password in the database
        user.password = hashedPassword;
        await user.save();

        // Return success response
        res.status(200).send('Password updated successfully.');

    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// admin function to return all editable user data
app.get('/api/admin/getUsers', async (req, res) => {
    try {
        // Fetch all users from the database
        const users = await User.find();

        // Create an array with user objects containing 'username', 'type', 'flag', 'lists', and 'reviews'
        const usersData = users
            .filter(user => user.username !== 'administrator') // Exclude users with username 'administrator'
            .map(user => {
                const userData = {
                    username: user.username,
                    type: user.type,
                    flag: user.flag,
                    lists: getListsData(user.lists),
                };

                return userData;
            });

        // Return the array as JSON
        res.json(usersData);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
});

// function to convert object properties to array for lists
function getListsData(listsObject) {
    if (!listsObject) {
        return [];
    }

    return Object.keys(listsObject).map(listName => {
        const listData = {
            listName: listName,
            description: listsObject[listName].description,
            visibility: listsObject[listName].visibility,
            ids: listsObject[listName].ids,
            reviews: getArrayOfReviews(listsObject[listName].reviews),
        };

        return listData;
    });
}

// function to convert object properties to array for reviews
function getArrayOfReviews(reviewsObject) {
    if (!reviewsObject) {
        return [];
    }

    return Object.keys(reviewsObject).map(reviewUsername => ({
        reviewUsername: reviewUsername,
        comment: reviewsObject[reviewUsername].comment,
        rating: reviewsObject[reviewUsername].rating,
        visibility: reviewsObject[reviewUsername].visibility,
        reviewId: reviewsObject[reviewUsername].reviewId,
        // Add other review properties as needed
    }));
}

// function to change user type to admin
app.post('/api/admin/changeType', async (req, res) => {
    try {
        const { username, type } = req.body;

        // Update the user's type in the database
        const updatedUser = await User.findOneAndUpdate(
            { username: username },
            { $set: { type: type } }
            
        );

        if (!updatedUser) {
            // User not found
            return res.status(404).json({ error: 'User not found.' });
        }

        res.status(200).json(updatedUser);
    } catch (error) {
        console.error('Error changing user type:', error);
        res.status(500).send('Internal Server Error');
    }
});

// function to change user flag
app.post('/api/admin/changeFlag', async (req, res) => {
    try {
        const { username, flag } = req.body;

        // Update the user's flag in the database
        const updatedUser = await User.findOneAndUpdate(
            { username: username },
            { $set: { flag: flag } }
        );

        if (!updatedUser) {
            // User not found
            return res.status(404).json({ error: 'User not found.' });
        }

        res.status(200).json(updatedUser);
    } catch (error) {
        console.error('Error changing user flag:', error);
        res.status(500).send('Internal Server Error');
    }
});

//function to change review visibility
app.post('/api/admin/changeReviewVisibility', async (req, res) => {
    const { listName, reviewId, reviewUsername, visibility } = req.body;

    try {
        // Find the user in the database
        const user = await User.findOne({
            [`lists.${listName}.reviews.${reviewUsername}.reviewId`]: reviewId
        });

        if (!user) {
            res.status(404).send(`Review with ID ${reviewId} not found.`);
            console.log("hi")
            return;
        }

        // Find the review and update its visibility
        const review = user.lists[listName].reviews[reviewUsername];

        if (review) {
            review.visibility = visibility;
            user.markModified('lists'); // Mark 'lists' as modified to trigger saving in MongoDB
            await user.save();

            res.status(200).send(`Visibility for review with ID ${reviewId} changed to ${visibility}`);
        } else {
            res.status(404).send(`Review with ID ${reviewId} not found.`);
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

