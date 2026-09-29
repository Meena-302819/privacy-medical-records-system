// =========================================================
// SECURE MEDICAL RECORDS SYSTEM
// DASHBOARD JAVASCRIPT
// =========================================================


// =========================================================
// DASHBOARD INITIALIZATION
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        initializeDashboard();

    }
);


// =========================================================
// INITIALIZE DASHBOARD
// =========================================================

function initializeDashboard() {

    animateDashboardCards();

    initializeSecurityStatus();

    initializeDashboardClock();

}


// =========================================================
// ANIMATE DASHBOARD CARDS
// =========================================================

function animateDashboardCards() {

    const cards =
        document.querySelectorAll(
            ".stat-card, .quick-action, .dashboard-panel"
        );


    cards.forEach(
        function (card, index) {

            card.style.opacity = "0";

            card.style.transform =
                "translateY(10px)";


            setTimeout(
                function () {

                    card.style.transition =
                        "opacity 0.35s ease, transform 0.35s ease";

                    card.style.opacity = "1";

                    card.style.transform =
                        "translateY(0)";

                },
                index * 60
            );

        }
    );

}


// =========================================================
// SECURITY STATUS
// =========================================================

function initializeSecurityStatus() {

    const statusItems =
        document.querySelectorAll(
            ".security-status-item"
        );


    statusItems.forEach(
        function (item) {

            item.addEventListener(
                "mouseenter",
                function () {

                    item.style.background =
                        "#f8fafc";

                }
            );


            item.addEventListener(
                "mouseleave",
                function () {

                    item.style.background =
                        "transparent";

                }
            );

        }
    );

}


// =========================================================
// DASHBOARD CLOCK
// =========================================================

function initializeDashboardClock() {

    const clock =
        document.querySelector(
            "[data-dashboard-clock]"
        );


    if (!clock) {
        return;
    }


    updateDashboardClock(clock);


    setInterval(
        function () {

            updateDashboardClock(clock);

        },
        1000
    );

}


function updateDashboardClock(clock) {

    const now = new Date();


    const hours =
        String(
            now.getHours()
        ).padStart(2, "0");


    const minutes =
        String(
            now.getMinutes()
        ).padStart(2, "0");


    const seconds =
        String(
            now.getSeconds()
        ).padStart(2, "0");


    clock.textContent =
        `${hours}:${minutes}:${seconds}`;

}


// =========================================================
// SECURITY ALERT ROW HIGHLIGHT
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const alertRows =
            document.querySelectorAll(
                ".security-alert-table tbody tr"
            );


        alertRows.forEach(
            function (row) {

                row.addEventListener(
                    "mouseenter",
                    function () {

                        row.style.background =
                            "#fff7ed";

                    }
                );


                row.addEventListener(
                    "mouseleave",
                    function () {

                        row.style.background =
                            "";

                    }
                );

            }
        );

    }
);


// =========================================================
// REFRESH DASHBOARD
// =========================================================

function refreshDashboard() {

    window.location.reload();

}