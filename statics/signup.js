$(function() {
    $('#btnSignUp').click(function() {
 
        $.ajax({
            url: '/showSignUp',
            data: $('form').serialize(),
            type: 'POST',
            success: function(response) {
                console.log(response);
		window.location.replace = "/upOrDown";
            },
            error: function(error) {
                console.log(error);
            }
        });
    });
});
