jQuery.fn.dataTable.render.ellipsis = function ( cutoff , linkurl=false, linktarget) {
  var esc = function ( t ) {
      return t
          .replace( /&/g, '&amp;' )
          .replace( /</g, '&lt;' )
          .replace( />/g, '&gt;' )
          .replace( /"/g, '&quot;' );
  };
  return function ( d, type, row ) {
    // Order, search and type get the original data

    if ( type !== 'display' ) {
      return d;
    }

    if ( typeof d !== 'number' && typeof d !== 'string' ) {
      return d;
    }

    d = d.toString(); // cast numbers

    if ( d.length <= cutoff ) {
      displaytext=d
    }
    else
    {
      displaytext='<span class="ellipsis" title="' + esc(d) + '">'+d.substr(0,cutoff)+'</span><span class=\"no-show\">' + d.substr(cutoff)+'</span>';
    }

    if (linkurl) {
      rettext='<a  href="'+eval(linktarget)+'">'+displaytext+'</a>';
      return rettext;
    }

    return displaytext;

  };
};

jQuery.fn.dataTable.render.ellipsisAltText = function ( cutoff , linkurl=false, linktarget, tipdatakey) {
  var esc = function ( t ) {
      return t
          .replace( /&/g, '&amp;' )
          .replace( /</g, '&lt;' )
          .replace( />/g, '&gt;' )
          .replace( /"/g, '&quot;' );
  };
  return function ( d, type, row ) {
    // Order, search and type get the original data
    var tipdata = row[tipdatakey];
    if ( type !== 'display' ) {
      return d;
    }

    if ( typeof d !== 'number' && typeof d !== 'string' ) {
      return d;
    }

    d = d.toString(); // cast numbers

    if ( d.length <= cutoff ) {
      displaytext='<span title="'+ esc(tipdata) + '">'+d+'</span>';
    }
    else
    {
      tipdata=d+" | "+tipdata
      displaytext='<span class="ellipsis" title="' + esc(tipdata) + '">'+d.substr(0,cutoff)+'</span><span class=\"no-show\">' + d.substr(cutoff)+'</span>';
    }
    if (linkurl) {
      rettext='<a  href="'+eval(linktarget)+'">'+displaytext+'</a>';
      return rettext;
    }

    return displaytext;

  };
};

function ellipsisTooltip(d,cutoff,tipdata) {
  var esc = function ( t ) {
      return t
          .replace( /&/g, '&amp;' )
          .replace( /</g, '&lt;' )
          .replace( />/g, '&gt;' )
          .replace( /"/g, '&quot;' );
  };
  if (tipdata === undefined) { tipdata = d;}
  if ( typeof d !== 'number' && typeof d !== 'string' ) {
    return d;
  }
  d = d.toString(); // cast numbers
  if ( d.length <= cutoff ) {
    displaytext='<span title="'+esc(tipdata)+'">'+d+'</span';
  }
  else
  {
    displaytext='<span class="ellipsis" title="' + esc(tipdata) + '">'+d.substr(0,cutoff)+'</span><span class=\"no-show\">' + d.substr(cutoff)+'</span>';
  }
  return displaytext;

}
