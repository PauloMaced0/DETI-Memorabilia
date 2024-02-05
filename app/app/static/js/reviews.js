$(document).ready(function() {
    const showMore = document.querySelector('.show-more');
    const reviewsList = document.querySelector('.reviews-list');

    $(".show-more").click(function (e) { 
        e.preventDefault();
        const toggle = showMore.getAttribute('data-toggle');

        if (toggle === "more") {
            // Show all reviews
            reviewsList.querySelectorAll('li').forEach(li => {
                li.style.display = 'block';
            });
            showMore.textContent = "Show less";
            showMore.setAttribute('data-toggle', 'less');
        } else {
            // Hide extra reviews
            reviewsList.querySelectorAll('li:nth-child(n+4)').forEach(li => {
                li.style.display = 'none';
            });
            showMore.textContent = "Show more";
            showMore.setAttribute('data-toggle', 'more');
        } 
    });
});