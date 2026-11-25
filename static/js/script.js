document.addEventListener("DOMContentLoaded", function () {

  const sidebar = document.querySelector(".sidebar");

  if (sidebar) {

    const toggle = document.createElement("button");

    toggle.className = "mobile-menu-toggle";
    toggle.type = "button";
    toggle.setAttribute(
      "aria-label",
      "Open navigation menu"
    );

    toggle.innerHTML =
      "<span></span><span></span><span></span>";

    document.body.appendChild(toggle);


    const backdrop = document.createElement("button");

    backdrop.className = "menu-backdrop";
    backdrop.type = "button";
    backdrop.setAttribute(
      "aria-label",
      "Close navigation menu"
    );

    document.body.appendChild(backdrop);


    const closeMenu = () => {

      document.body.classList.remove("menu-open");

      toggle.setAttribute(
        "aria-label",
        "Open navigation menu"
      );

    };


    toggle.addEventListener("click", () => {

      const open =
        document.body.classList.toggle("menu-open");

      toggle.setAttribute(
        "aria-label",
        open
          ? "Close navigation menu"
          : "Open navigation menu"
      );

    });


    backdrop.addEventListener(
      "click",
      closeMenu
    );


    sidebar
      .querySelectorAll("a")
      .forEach(link =>
        link.addEventListener(
          "click",
          closeMenu
        )
      );

  }


  document
    .querySelectorAll("[data-count]")
    .forEach(function (element) {

      const target =
        Number(element.dataset.count) || 0;

      if (!target) {
        return;
      }


      const start = performance.now();


      const tick = now => {

        const p = Math.min(
          (now - start) / 650,
          1
        );


        element.textContent =
          Math.round(
            target *
            (1 - Math.pow(1 - p, 3))
          );


        if (p < 1) {
          requestAnimationFrame(tick);
        }

      };


      element.textContent = "0";

      requestAnimationFrame(tick);

    });


  const search =
    document.querySelector("[data-global-search]");


  if (search) {

    document.addEventListener(
      "keydown",
      e => {

        if (
          (e.ctrlKey || e.metaKey) &&
          e.key.toLowerCase() === "k"
        ) {

          e.preventDefault();

          search.focus();

        }

      }
    );


    search.addEventListener(
      "input",
      () => {

        const q =
          search.value
            .trim()
            .toLowerCase();


        document
          .querySelectorAll(
            "table tr:not(:first-child)"
          )
          .forEach(row => {

            row.style.display =
              !q ||
              row.textContent
                .toLowerCase()
                .includes(q)
                ? ""
                : "none";

          });

      }
    );

  }

});