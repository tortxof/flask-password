$(document).ready(function() {
  $('#newusername').on('change keyup', function() {
    var username = $(this).val();
    $.getJSON('/userexists', {user: username}, function(data) {
      if (data.exists) {
        $('#newusername').css({'color': 'red'});
      }
      else {
        $('#newusername').css({'color': 'green'});
      }
    });
  });

  $(".clksel").click(function() {
    $(this).select();
  });
});
