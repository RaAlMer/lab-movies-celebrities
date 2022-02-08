// starter code in both routes/celebrities.routes.js and routes/movies.routes.js
const router = require("express").Router();

const Movie = require('../models/Movie.model');
const Celebrity = require('../models/Celebrity.model');

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');

// GET route to create a movie
router.get('/movies/create', isLoggedIn, (req, res) => {
    Celebrity.find()
    .then((dbCelebrities) => {
        res.render('movies/new-movie.hbs', {dbCelebrities});
    });
});

// POST route to save a new movie to the database
router.post('/movies/create', isLoggedIn, (req, res, next) => {
    const { title, genre, plot, cast } = req.body;
    Movie.create({ title, genre, plot, cast })
        .then(() => res.redirect('/movies'))
        .catch(() => res.render('movies/new-movie.hbs'));
});

// GET route to update a specific movie
router.get('/movies/:id/edit', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
  let movie;
 
  Movie.findById(id)
    .then(movieToEdit => {
      movie = movieToEdit;
    })
    .then(() => {
      Celebrity.find()
        .then(celebrities => {
          res.render("movies/edit-movie.hbs", {movie, celebrities});
        });
    });
});

// POST route to update a specific movie
router.post('/movies/:id/edit', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
  const { title, genre, plot, cast } = req.body;
 
  Movie.findByIdAndUpdate(id, { title, genre, plot, cast }, { new: true })
    .then(updatedMovie => res.redirect(`/movies/${updatedMovie.id}`))
    .catch(error => next(error));
});

// POST route to delete a movie from the database
router.post('/movies/:id/delete', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
 
  Movie.findByIdAndRemove(id)
    .then(() => res.redirect('/movies'))
    .catch(error => next(error));
});

// GET route to retrieve and display all the movies
router.get('/movies', isLoggedIn, (req, res, next) => {
    Movie.find()
      .then(allTheMoviesFromDB => {
        console.log('Retrieved movies from DB:', allTheMoviesFromDB);
        res.render('movies/movies.hbs', { movies: allTheMoviesFromDB });
      })
      .catch(error => {
        console.log('Error while getting the movies from the DB: ', error);
        next(error);
      });
  });

// GET route for displaying the movie details page
router.get('/movies/:id', isLoggedIn, (req, res, next) => {
  const { id } = req.params;
 
  Movie.findById(id)
    .populate('cast')
    .then(foundMovie => res.render('movies/movie-details.hbs', foundMovie))
    .catch(err => {
      console.log(`Error while getting a single movie from the  DB: ${err}`);
      next(err);
    });
});

module.exports = router;