// starter code in both routes/celebrities.routes.js and routes/movies.routes.js
const router = require("express").Router();

const Celebrity = require('../models/Celebrity.model.js');

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');

// GET route to create a celebrity
router.get('/celebrities/create', isLoggedIn, (req, res) => {
    res.render('celebrities/new-celebrity.hbs');
});

// POST route to save a new celebrity to the database
router.post('/celebrities/create', isLoggedIn, (req, res, next) => {
    const { name, occupation, catchPhrase } = req.body;
    Celebrity.create({ name, occupation, catchPhrase })
        .then(() => res.redirect('/celebrities'))
        .catch(() => res.render('celebrities/new-celebrity.hbs'));
});

// GET route to update a specific celebrity
router.get('/celebrities/:id/edit', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
 
  Celebrity.findById(id)
    .then(celebrityToEdit => {
      res.render("celebrities/edit-celebrity.hbs", {celebrityToEdit});
    });
});

// POST route to update a specific celebrity
router.post('/celebrities/:id/edit', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
  const { name, occupation, catchPhrase } = req.body;
 
  Celebrity.findByIdAndUpdate(id, { name, occupation, catchPhrase }, { new: true })
    .then(updatedCelebrity => res.redirect(`/celebrities/${updatedCelebrity.id}`))
    .catch(error => next(error));
});

// POST route to delete a celebrity from the database
router.post('/celebrities/:id/delete', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
 
  Celebrity.findByIdAndRemove(id)
    .then(() => res.redirect('/celebrities'))
    .catch(error => next(error));
});


// GET route to retrieve and display all the celebrities
router.get('/celebrities', isLoggedIn, (req, res, next) => {
    Celebrity.find()
      .then(allTheCelebritiesFromDB => {
        console.log('Retrieved celebrities from DB:', allTheCelebritiesFromDB);
        res.render('celebrities/celebrities.hbs', { celebrities: allTheCelebritiesFromDB });
      })
      .catch(error => {
        console.log('Error while getting the celebrities from the DB: ', error);
        // Call the error-middleware to display the error page to the user
        next(error);
      });
  });

// GET route for displaying the celebrity details page
router.get('/celebrities/:id', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
 
  Celebrity.findById(id)
    .then(foundCeleb => res.render('celebrities/celebrity-details.hbs', foundCeleb))
    .catch(err => {
      console.log(`Error while getting a single celebrity from the  DB: ${err}`);
      next(err);
    });
});

module.exports = router;