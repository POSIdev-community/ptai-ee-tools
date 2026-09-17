Behaviour.specify("select.ptai-scan-type", "ptai-scan-type", 0, function (select) {
    var step = select.closest(".repeated-chunk") || select.closest("form");
    if (!step) {
        return;
    }

    function update() {
        step.querySelectorAll(".ptai-scan-type-block").forEach(function (block) {
            block.style.display = block.getAttribute("data-scan-type") === select.value ? "" : "none";
        });
    }

    select.addEventListener("change", update);
    update();
});
