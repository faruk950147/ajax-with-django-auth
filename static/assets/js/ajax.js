$(document).ready(function () {
  $("#showHide").on("click", function(e){
    e.preventDefault()
    $("#icon").toggleClass("fa-eye")
  
    if($("#id_password, #id_password2, #id_current_password").attr("type") === "password"){
      $("#id_password, #id_password2, #id_current_password").attr("type", "text")
    }
    else{
      $("#id_password, #id_password2, #id_current_password").attr("type", "password")
    }
});
});
