var BASE64_CODE = [
  ".",
  "/",
  "A",
  "B",
  "C",
  "D",
  "E",
  "F",
  "G",
  "H",
  "I",
  "J",
  "K",
  "L",
  "M",
  "N",
  "O",
  "P",
  "Q",
  "R",
  "S",
  "T",
  "U",
  "V",
  "W",
  "X",
  "Y",
  "Z",
  "a",
  "b",
  "c",
  "d",
  "e",
  "f",
  "g",
  "h",
  "i",
  "j",
  "k",
  "l",
  "m",
  "n",
  "o",
  "p",
  "q",
  "r",
  "s",
  "t",
  "u",
  "v",
  "w",
  "x",
  "y",
  "z",
  "0",
  "1",
  "2",
  "3",
  "4",
  "5",
  "6",
  "7",
  "8",
  "9",
];

var INDEX_64 = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
  -1, -1, -1, -1, -1, -1, -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
  48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1,
];

function encode_base64(d, len) {
  var off = 0;
  var rs = [];
  var c1;
  var c2;
  if (len <= 0 || len > d.length) throw "Invalid len";
  while (off < len) {
    c1 = d[off++] & 0xff;
    rs.push(BASE64_CODE[(c1 >> 2) & 0x3f]);
    c1 = (c1 & 0x03) << 4;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 0x3f]);
      break;
    }
    c2 = d[off++] & 0xff;
    c1 |= (c2 >> 4) & 0x0f;
    rs.push(BASE64_CODE[c1 & 0x3f]);
    c1 = (c2 & 0x0f) << 2;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 0x3f]);
      break;
    }
    c2 = d[off++] & 0xff;
    c1 |= (c2 >> 6) & 0x03;
    rs.push(BASE64_CODE[c1 & 0x3f]);
    rs.push(BASE64_CODE[c2 & 0x3f]);
  }
  return rs.join("");
}

function getByte(c) {
  var ret = 0;
  try {
    var b = c.charCodeAt(0);
  } catch (err) {
    b = c;
  }
  if (b > 127) {
    return -128 + (b % 128);
  } else {
    return b;
  }
}

function char64(x) {
  var code = x.charCodeAt(0);
  if (code < 0 || code > INDEX_64.length) {
    return -1;
  }
  return INDEX_64[code];
}

function decode_base64(s, maxolen) {
  var off = 0;
  var slen = s.length;
  var olen = 0;
  var rs = [];
  var c1, c2, c3, c4, o;

  if (maxolen <= 0) throw "Invalid maxolen";

  while (off < slen - 1 && olen < maxolen) {
    c1 = char64(s.charAt(off++));
    c2 = char64(s.charAt(off++));
    if (c1 == -1 || c2 == -1) {
      break;
    }
    o = getByte(c1 << 2);
    o |= (c2 & 0x30) >> 4;
    rs.push(String.fromCharCode(o));
    if (++olen >= maxolen || off >= slen) {
      break;
    }
    c3 = char64(s.charAt(off++));
    if (c3 == -1) {
      break;
    }
    o = getByte((c2 & 0x0f) << 4);
    o |= (c3 & 0x3c) >> 2;
    rs.push(String.fromCharCode(o));
    if (++olen >= maxolen || off >= slen) {
      break;
    }
    c4 = char64(s.charAt(off++));
    o = getByte((c3 & 0x03) << 6);
    o |= c4;
    rs.push(String.fromCharCode(o));
    ++olen;
  }
  var ret = [];

  for (off = 0; off < olen; off++) {
    ret.push(getByte(rs[off]));
  }

  return ret;
}

console.log(decode_base64(encode_base64([10, 0, 10], 3), 3));
