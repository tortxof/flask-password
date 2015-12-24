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

  new Clipboard('.cb-copy');

});
