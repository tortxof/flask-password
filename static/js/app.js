// Workaround for clipboard.js in bootstrap modal.
$.fn.modal.Constructor.prototype.enforceFocus = function () {};

$("#newusername").on("change keyup", function () {
  var username = $(this).val();
  $.getJSON(username_available_endpoint, { user: username }, function (data) {
    if (data.available) {
      $("#newusername")
        .parent()
        .addClass("has-success has-feedback")
        .removeClass("has-error")
        .find("span")
        .addClass("glyphicon-ok")
        .removeClass("glyphicon-remove");
    } else {
      $("#newusername")
        .parent()
        .addClass("has-error has-feedback")
        .removeClass("has-success")
        .find("span")
        .addClass("glyphicon-remove")
        .removeClass("glyphicon-ok");
    }
  });
});

function showTooltip(elem) {
  var success_elem = document.createElement("div");
  success_elem.className = "cb-copy-success";
  success_elem.textContent = "Copied";
  $(elem).append(success_elem);
  $(success_elem)
    .delay(1000)
    .fadeOut(500, function () {
      success_elem.parentNode.removeChild(success_elem);
    });
}

var passwords_template = Handlebars.compile($("#passwords_template").html());
function renderPasswords() {
  $.getJSON(generate_passwords_json_endpoint, function (pw_json) {
    var passwords_html = passwords_template(pw_json.passwords);
    passwords_html += passwords_template(pw_json.pins);
    passwords_html += passwords_template(pw_json.keys);
    passwords_html += passwords_template(pw_json.phrases);
    $("#genpw-modal-body").html(passwords_html);
  });
}
$("#genpw-open").click(function (evt) {
  evt.preventDefault();
  renderPasswords();
  $("#genpw-modal").modal();
});
$("#genpw-refresh").click(renderPasswords);

var clipboard = new Clipboard(".cb-copy");
clipboard.on("success", function (e) {
  showTooltip(e.trigger);
});

function showPassword(e) {
  if (e.target.classList.contains("show-pw")) {
    e.preventDefault();
    var password =
      e.target.parentElement.querySelector("button.cb-copy").dataset
        .clipboardText;
    e.target.parentElement.querySelector(".password").innerText = password;
  }
}

function hidePassword(e) {
  if (e.target.classList.contains("show-pw")) {
    e.preventDefault();
    e.target.parentElement.querySelector(".password").innerHTML =
      "&bullet;".repeat(8);
  }
}

document
  .getElementById("main-container")
  .addEventListener("mousedown", showPassword);

document
  .getElementById("main-container")
  .addEventListener("touchstart", showPassword);

document
  .getElementById("main-container")
  .addEventListener("mouseup", hidePassword);

document
  .getElementById("main-container")
  .addEventListener("touchend", hidePassword);

var pageload_time = new Date().getTime() / 1000;
var elSessionTimeFg = document.querySelector(".session-time .fg");

function updateSessionCountdown() {
  var seconds_elapsed = new Date().getTime() / 1000 - pageload_time;
  var fraction_time_left = (refresh_time - seconds_elapsed) / total_time;
  elSessionTimeFg.style.strokeDashoffset = -63 * (1 - fraction_time_left);
}

if (refresh_time !== null) {
  updateSessionCountdown();
  document.querySelector(".session-time").style.display = "block";
  var session_countdown_interval = window.setInterval(
    updateSessionCountdown,
    1000
  );
  window.setTimeout(function () {
    window.clearInterval(session_countdown_interval);
  }, refresh_time * 1000);
  window.setTimeout(function () {
    window.location.reload(true);
  }, (refresh_time + 10) * 1000);
}

document.querySelectorAll(".record-date").forEach(function (el) {
  el.innerText = moment
    .duration(-parseInt(el.dataset.seconds), "seconds")
    .humanize(true);
});
