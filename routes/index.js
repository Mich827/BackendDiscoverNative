var express = require("express");
var router = express.Router();
const fetch = require("node-fetch");

const NEWS_API_KEY = process.env.NEWS_API_KEY;
const MOVIES_API_KEY = process.env.MOVIES_API_KEY;

//route for get media api

router.get("/articles", (req, res) => {
  const limit = 30; //nombre d'articles à recupèrer
  fetch(
    `https://newsapi.org/v2/everything?sources=the-verge&apiKey=${NEWS_API_KEY}&pageSize=${limit}`
  )
    .then((response) => response.json())
    .then((data) => {
      if (data.status === "ok") {
        res.json({ articles: data.articles });
      } else {
        res.json({ articles: [] });
      }
    });
});

//route for get movies api
router.get("/movies", (req, res) => {
  fetch(`https://api.themoviedb.org/3/discover/movie?api_key=${MOVIES_API_KEY}`)
    .then((response) => response.json())
    .then((data) => {
      if (data.results) {
        res.json({ movies: data.results });
      } else {
        res.json({ movies: [] });
      }
    });
});
module.exports = router;
