mbitmax = 30;
function VerifyAddr(addr, nwclass, ipv) {
  var len = ipv
  var temp = [];
  var max = 0;
  var index = 0;
  if (ipv === 4)
    max = 255;
  else if (ipv === 6)
    max = 0xffff;
  if (len > addr.length)
    return ClassObj()[nwclass].dip;
  while (index < len) {
    temp[index] = addr[index];
    index++;
  }
  addr = temp;
  index = 0;
  if (addr[index] == 0 && nwclass != "cidr") addr[index] = 1;
  while (index < len) {
    if (addr[index] < 0 || addr[index] === "")
      addr[index] = 0;
    else if (addr[index] > max)
      addr[index] = max;
    else if (isNaN(addr[index])) {
      addr = ClassObj()[nwclass].dip;
      break;
    }
    index += 1;
  }
  return addr;
}
function VerifyMask(mask, ipv) {
  var len = ipv
  var max = 0;
  if (ipv === 4)
    max = 255;
  else if (ipv === 6)
    max = 0xffff;
  var legalmasks = [255, 254, 252, 248, 240, 224, 192, 128, 0];
  var maskindex = 0;
  var legalindex = 0;
  var index = 0;
  var temp = [];
  while (index < len) {
    if (isNaN(mask[index]) || mask[index] === "")
      mask[index] = 0;
    temp[index] = mask[index];
    index++;
  }
  mask = temp;
  while (maskindex < len) {
    while (legalindex < legalmasks.length) {
      if (mask[maskindex] == legalmasks[legalindex])
        break;
      else if (legalindex == (legalmasks.length-1))
        mask[maskindex] = 0;
      legalindex += 1;
    }
    if (mask[maskindex] != 255) {
      maskindex += 1;
      while(maskindex < len) {
        mask[maskindex] = 0;
        maskindex += 1;
      }
    }
    maskindex += 1;
  }
  if (mask[3] > 252) mask[3] = 252;
  return mask;
}
function ClassObj() {
  return {
    a: {
      id: "A",
      llim: 0,
      ulim: 127,
      oct: "1-126",
      bits: 8,
      dip: [10,0,0,1],
      dsm: [255,0,0,0]
    },
    b: {
      id: "B",
      llim: 128,
      ulim: 191,
      oct: "128-191",
      bits: 16,
      dip: [172,16,0,1],
      dsm: [255,255,0,0]
    },
    c: {
      id: "C",
      llim: 192,
      ulim: 223,
      oct: "192-223",
      bits: 24,
      dip: [192,168,0,1],
      dsm: [255,255,255,0]
    },
    cidr: {
      id: "cidr",
      llim: 0,
      ulim: 255,
      oct: "ALL THE RANGES",
      bits: 0,
      dip: [10,0,0,1],
      dsm: [255,0,0,0]
    }
  };
}
function GetClassObj(ipArr) {
  var classes = ['a', 'b', 'c'];
  var classindex = 0;
  for (classindex = 0; classindex < 3; classindex++) {
    if (ipArr[0] <= ClassObj()[classes[classindex]].ulim && ipArr[0] >= ClassObj()[classes[classindex]].llim)
      return ClassObj()[classes[classindex]];
  }
  ipArr[0] = 223;
  return {
    id: "C",
    oct: "193-221",
    bits: 24,
    ip: ipArr,
    dsm: [255,255,255,0]
  }
}
function calcMaskbits(smaskArr) {
  var mbits = 0;
  var bits  = 7;
  var i     = 0;
  var cmask = [];
  while (i < 4)
  {
    cmask[i] = smaskArr[i];
    i += 1;
  }
  i = 0;
  while (i < 4)
  {
    bits = 7; 
    while ((bits >= 0) && (cmask[i]  >= Math.pow(2,bits)))
    {
      cmask[i] -= Math.pow(2,bits);
      mbits += 1;
      bits -= 1;
    }
    i += 1;
  }
  return mbits;
}
function calcRest(ipv, ipArr, smaskArr, nbits) {
  var o = {
    wmask: [],
    netaddr: [],
    bcaddr: []
  };
  ipv = 4;
  index = 0;
  
  while (index < ipv) {
    o.wmask[index] = 255 - smaskArr[index];
    index += 1;
  }
  
  o.mbits = calcMaskbits(smaskArr);
  o.sbits = o.mbits - nbits;
  o.hbits = 32 - o.mbits;
  o.hosts = Math.pow(2, o.hbits) - 2;
  o.subs  = Math.pow(2, o.sbits);
  if (o.hosts < 0) o.hosts = 0;
  if (o.subs < 0) o.subs = 0;
  
  index = 0;
  while (index < ipv) {
    o.netaddr[index] = ipArr[index] & smaskArr[index];
    o.bcaddr[index] = ipArr[index] | o.wmask[index];
    index += 1;
  }
  
  return o;
}
function calchosts(nbits, nhosts) {
  var o = {};
  var hostbits = 0;
  
  while (Math.pow(2, hostbits) - 2 < nhosts && hostbits != (32 - nbits)) {
    hostbits += 1;
  }
  o.nhosts = Math.pow(2, hostbits) - 2;
  o.mbits = 32 - hostbits;
  
  return o;
}
function calcsubs(nbits, nsubs) {
  var o = {};
  var subbits = 0; 
  
  while (Math.pow(2, subbits) < nsubs && (subbits + nbits) != mbitmax) {
    subbits += 1;
  }
  
  o.nsubs = Math.pow(2, subbits);
  o.mbits = subbits + nbits;
  return o;
}
function GetMask(mbits) {
  var mask = [0,0,0,0];
  var cmaskBits = mbits;
  var bitmask = 128;
    for (var bit = 0; Math.floor(bit/8) < 4 && cmaskBits; bit++, cmaskBits--) 
    {
      mask[Math.floor(bit/8)] |= bitmask;
      if (1 === bitmask)
      {
        bitmask = 128;
      }
      else
      {
        bitmask >>= 1;
      }
    }
  return mask;
}