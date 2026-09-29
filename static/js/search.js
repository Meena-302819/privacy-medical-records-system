/* =========================================================
   PRIVACY-PRESERVING SEARCH
   Search Page JavaScript
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {

    const searchForm = document.getElementById("searchForm");
    const searchInput = document.getElementById("searchInput");
    const searchButton = document.getElementById("searchButton");


    /* =====================================================
       SEARCH FORM VALIDATION
       ===================================================== */

    if (searchForm && searchInput && searchButton) {

        searchForm.addEventListener("submit", function (event) {

            const query = searchInput.value.trim();

            if (query.length === 0) {

                event.preventDefault();

                searchInput.focus();

                return;
            }


            /* Prevent extremely long search input */

            if (query.length > 200) {

                event.preventDefault();

                alert(
                    "Search query is too long. " +
                    "Please enter a shorter search term."
                );

                searchInput.focus();

                return;
            }


            /* Show loading state */

            searchButton.classList.add("loading");

            searchButton.disabled = true;

            searchButton.innerHTML =
                '<i class="fa-solid fa-spinner"></i> Searching...';

        });

    }


    /* =====================================================
       ENTER KEY SEARCH
       ===================================================== */

    if (searchInput) {

        searchInput.addEventListener("keydown", function (event) {

            if (event.key === "Enter") {

                if (searchInput.value.trim().length === 0) {

                    event.preventDefault();

                    searchInput.focus();

                }

            }

        });

    }


    /* =====================================================
       AUTO FOCUS
       ===================================================== */

    if (searchInput) {

        searchInput.focus();

        /*
         * Move cursor to the end if an existing
         * search query is present.
         */

        const value = searchInput.value;

        searchInput.setSelectionRange(
            value.length,
            value.length
        );

    }


    /* =====================================================
       SECURITY INFORMATION
       ===================================================== */

    console.log(
        "Privacy-Preserving Search initialized."
    );

    console.log(
        "Search keywords are converted to HMAC-SHA256 tokens."
    );

});