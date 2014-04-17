function Update(ipv, f) {
  var octField    = document.getElementById("octet");
  var ipField     = document.getElementById("ipaddr");
  var mbitField   = document.getElementById("maskbits");
  var smaskField  = document.getElementById("subnetmask");
  var wmaskField  = document.getElementById("wildcardmask");
  var hostsField  = document.getElementById("hosts");
  var subsField   = document.getElementById("subs");
  var sAddrField  = document.getElementById("subnetaddr");
  var bcField     = document.getElementById("broadcastaddr");
  var hostRange   = document.getElementById("addrrange");
  var nbitField   = document.getElementById("netbits");
  var sbitField   = document.getElementById("subbits");
  var hbitField   = document.getElementById("hostbits");
  var netRadios   = document.getElementsByName("netwClass");
  for (var index = 0;!netRadios[index].checked;index++);
  var nwclass = netRadios[index].value;
  if (typeof(f) === 'undefined' || f()) {
    smaskField.value = VerifyMask(smaskField.value.split("."), ipv).join(".");
    temp = VerifyAddr(ipField.value.split("."), nwclass, ipv);
    if (typeof(temp) === "string") {
        ipField.value = temp;
        return 0;
    }
    else {
      ipField.value = temp.join(".");
      var ipArr     = ipField.value.split(".");
      var smaskArr  = smaskField.value.split(".");
      var saddrArr  = sAddrField.value.split(".");
      var wmaskArr  = wmaskField.value.split(".");
      var bcaddrArr = bcField.value.split(".");
      var faddr;
      var laddr;
      var index     = 1;
      if (netRadios[0].checked === false) {
        var nclassObj = GetClassObj(ipArr);
        if (nclassObj.ip) {   
          ipArr         = nclassObj.ip;
          ipField.value = ipArr.join(".");
        }
        octField.value = nclassObj.oct;
        nbitField.value = nclassObj.bits;
        
        while (index < netRadios.length) {
          if (netRadios[index].id === nclassObj.id) {
            netRadios[index].checked = true;
            break;
          }
          index += 1;
        }
        index = 0;
        while (index < smaskArr.length) {   
          smaskArr[index] |= nclassObj.dsm[index];
          index += 1;
        }
        smaskField.value = smaskArr.join(".");
      }
      var details = calcRest(ipv, ipArr, smaskArr, nbitField.value);
      wmaskField.value  = details.wmask.join(".");      
      mbitField.value   = details.mbits;
      sbitField.value   = details.sbits;
      hbitField.value   = details.hbits;
      hostsField.value  = details.hosts;
      subsField.value   = details.subs;
      sAddrField.value  = details.netaddr.join(".");
      bcField.value     = details.bcaddr.join(".");
      details.netaddr[3] += 1; details.bcaddr[3] -= 1;
      hostRange.value = details.netaddr.join(".") + " - " + details.bcaddr.join(".");
      var classString = "Classles";
      if (netRadios[0].checked == false) {
      classString = "Class: " + nclassObj.id + "%0AFirst Octet Range: " + octField.value;
      }
    }
  }
}
var fmaskbits = function () {
  var mbitField   = document.getElementById("maskbits");
  var smaskField  = document.getElementById("subnetmask");
  smaskField.value = GetMask(mbitField.value).join(".");
  return true;
}
var fnetclass = function() {
  var netRadios   = document.getElementsByName("netwClass");
  var ipField     = document.getElementById("ipaddr");
  var classindex = 1;
  while (classindex < 4) {
    if (netRadios[classindex].checked) {
      ipField.value = ClassObj()[netRadios[classindex].value].dip.join(".");
      classindex = 4;
    }
    classindex += 1;
  }
  return true;
}
var fhosts = function () {
  var nbitField   = document.getElementById("netbits");
  var hostsField  = document.getElementById("hosts");
  var mbitField   = document.getElementById("maskbits");
  var details = calchosts(+nbitField.value, hostsField.value);
  hostsField.value = details.nhosts;
  mbitField.value  = details.mbits;
  fmaskbits();
  return true;
}
var fsubs = function () {
  var nbitField   = document.getElementById("netbits");
  var subsField   = document.getElementById("subs");
  var mbitField   = document.getElementById("maskbits");
  var details = calcsubs(+nbitField.value, subsField.value);
  subsField.value  = details.nsubs;
  mbitField.value  = details.mbits;
  fmaskbits();
  return true;
}
var fsbits = function () {
  var nbitField   = document.getElementById("netbits");
  var mbitField   = document.getElementById("maskbits");
  var sbitField   = document.getElementById("subbits");
  if (+sbitField.value > (30 - +nbitField.value)) sbitField.value = 30 - +nbitField.value;
  mbitField.value = +nbitField.value + +sbitField.value;
  fmaskbits();
  return true;
}
var fhbits = function () {
  var nbitField   = document.getElementById("netbits");
  var mbitField   = document.getElementById("maskbits");
  var hbitField   = document.getElementById("hostbits");
  if (hbitField.value > (32 - +nbitField.value)) hbitField.value = 32 - nbitField.value;
  console.log();
  mbitField.value = 32 - hbitField.value;
  fmaskbits();
  return true;
}