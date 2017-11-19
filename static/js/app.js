// Workaround for clipboard.js in bootstrap modal.
$.fn.modal.Constructor.prototype.enforceFocus = function() {}

$('#newusername').on('change keyup', function() {
  var username = $(this).val()
  $.getJSON(username_available_endpoint, { user: username }, function(data) {
    if (data.available) {
      $('#newusername')
        .parent()
        .addClass('has-success has-feedback')
        .removeClass('has-error')
        .find('span')
        .addClass('glyphicon-ok')
        .removeClass('glyphicon-remove')
    } else {
      $('#newusername')
        .parent()
        .addClass('has-error has-feedback')
        .removeClass('has-success')
        .find('span')
        .addClass('glyphicon-remove')
        .removeClass('glyphicon-ok')
    }
  })
})

function showTooltip(elem) {
  var success_elem = document.createElement('div')
  success_elem.className = 'cb-copy-success'
  success_elem.textContent = 'Copied'
  $(elem).append(success_elem)
  $(success_elem)
    .delay(1000)
    .fadeOut(500, function() {
      success_elem.parentNode.removeChild(success_elem)
    })
}

var passwords_template = Handlebars.compile($('#passwords_template').html())
function renderPasswords() {
  $.getJSON(generate_passwords_json_endpoint, function(pw_json) {
    var passwords_html = passwords_template(pw_json.passwords)
    passwords_html += passwords_template(pw_json.pins)
    passwords_html += passwords_template(pw_json.keys)
    passwords_html += passwords_template(pw_json.phrases)
    $('#genpw-modal-body').html(passwords_html)
  })
}
$('#genpw-open').click(function(evt) {
  evt.preventDefault()
  renderPasswords()
  $('#genpw-modal').modal()
})
$('#genpw-refresh').click(renderPasswords)

var clipboard = new Clipboard('.cb-copy')
clipboard.on('success', function(e) {
  showTooltip(e.trigger)
})

$('.show-pw').mousedown(function() {
  var password = $(this)
    .prev('.cb-copy')
    .data('clipboard-text')
  $(this)
    .next('.password')
    .text(password)
})

$('.show-pw').mouseup(function() {
  var bullets = ''
  for (var i = 0; i < 8; i++) {
    bullets += '&bullet;'
  }
  $(this)
    .next('.password')
    .html(bullets)
})

if (refresh_time !== null) {
  var fraction_time_left = refresh_time / total_time
  var seconds_elapsed = 0
  var session_countdown_interval = window.setInterval(function() {
    seconds_elapsed++
    fraction_time_left = (refresh_time - seconds_elapsed) / total_time
    document.querySelector('.session-time .fg').style.strokeDashoffset =
      -63 * (1 - fraction_time_left)
    document.querySelector('.session-time').style.display = 'block'
  }, 1000)
  window.setTimeout(function() {
    window.clearInterval(session_countdown_interval)
  }, refresh_time * 1000)
  window.setTimeout(function() {
    window.location.reload(true)
  }, (refresh_time + 10) * 1000)
}
