document.addEventListener("DOMContentLoaded", function () {

    // =====================================================
    // SIDEBAR
    // =====================================================

    const menuToggle =
        document.getElementById("menuToggle");

    const sidebar =
        document.getElementById("sidebar");


    if (menuToggle && sidebar) {

        menuToggle.addEventListener(
            "click",
            function () {

                sidebar.classList.toggle("open");

            }
        );

    }


    // =====================================================
    // FLASH MESSAGE CLOSE
    // =====================================================

    document
        .querySelectorAll(".flash-close")
        .forEach(function (button) {

            button.addEventListener(
                "click",
                function () {

                    const message =
                        button.closest(".flash-message");

                    if (message) {

                        message.style.opacity = "0";

                        message.style.transform =
                            "translateX(20px)";

                        setTimeout(
                            function () {

                                message.remove();

                            },
                            250
                        );

                    }

                }
            );

        });


    // =====================================================
    // AUTO HIDE FLASH MESSAGES
    // =====================================================

    setTimeout(function () {

        document
            .querySelectorAll(".flash-message")
            .forEach(function (message) {

                message.style.opacity = "0";

                setTimeout(
                    function () {
                        message.remove();
                    },
                    300
                );

            });

    }, 5000);


    // =====================================================
    // ACTIVE SIDEBAR LINK
    // =====================================================

    const currentPath =
        window.location.pathname;

    document
        .querySelectorAll(".nav-item")
        .forEach(function (link) {

            const href =
                link.getAttribute("href");

            if (
                href &&
                href !== "/" &&
                currentPath === href
            ) {

                link.classList.add("active");

            }

        });

});