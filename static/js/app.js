$(document).ready(function() {

  $('#newusername').on('change keyup', function() {
    var username = $(this).val();
    $.getJSON('/username-available', {user: username}, function(data) {
      if (data.available) {
        $('#newusername').parent().addClass("has-success has-feedback").removeClass("has-error").find("span").addClass("glyphicon-ok").removeClass("glyphicon-remove");
      }
      else {
        $('#newusername').parent().addClass("has-error has-feedback").removeClass("has-success").find("span").addClass("glyphicon-remove").removeClass("glyphicon-ok");
      }
    });
  });

  function showTooltip(elem) {
    var success_elem = document.createElement('div');
    success_elem.className = 'cb-copy-success';
    success_elem.textContent = 'Copied';
    $(elem).before(success_elem);
    $(success_elem).delay(1000).fadeOut(500, function() {
      success_elem.parentNode.removeChild(success_elem);
    })
  }

  var clipboard = new Clipboard('.cb-copy');
  clipboard.on('success', function(e) {
    showTooltip(e.trigger);
  });

});
