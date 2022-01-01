function vuln_ignore_prompt(key, row) {
  if (key == "ignore") {
    $.ajax({
      url: "/subform/addignorelist",
      success: function(newHTML, textStatus, jqXHR) {
        $(newHTML).appendTo('body').modal();
        $('#modal-vuln_id-option').text(row.vuln_id);
        $('#modal-artifact_name-option').text(row.artifact_name);
        $('#modal-artifact_version-option').text(row.artifact_version);
        $('#modal-namespace-option').text(row.namespace);
        $('#modal-container-option').text(row.container);
        $('#modal-image-option').text(row.image);
        $('#modal-image_id-option').text(row.image_id_digest);
        $('#modalform').modal('show');
      },
      error: function(jqXHR, textStatus, errorThrown) {
        alert("Error processing add request");
      },
      method: "GET"
    });
  }
  return true;
}

$(document).on($.modal.OPEN, '#responseform', function (e) {
    setTimeout(() => {
      $.modal.close();
    },1500);
});

$(document).on($.modal.CLOSE, '#responseform', function (e) {
  window.location.replace(window.location.href)
});


$(document).on("click","#addform-submit", function() {
    $('#messageform-message')[0].innerHTML = 'Processing Add Request/Refreshing View, Please Wait'
    $('#messageform').modal('show');
    $.ajax({
      url: $(this).attr('href'),
      success: function(newHTML, textStatus, jqXHR) {
        $(newHTML).appendTo('body');
        $('#responseform').modal('show');
      },
      error: function(jqXHR, textStatus, errorThrown) {
        alert("Error processing add request");
      },
      data: $('#ignorelist-form').serialize(),
      method: "POST"


    });

    return false;

}
);
