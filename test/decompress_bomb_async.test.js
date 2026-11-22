"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");
const Methods = require("../methods");

// Regression test for GHSA-c6fg-446q-cg94:
// getDataAsync() inflated DEFLATED entries through a zlib stream, and zlib
// streams ignore the maxOutputLength option that caps the synchronous
// getData() path. A small crafted archive that understates an entry's
// uncompressed size could therefore be decompressed without any limit through
// the async API (readFileAsync, readAsTextAsync, extractAllToAsync, ...).
// The async path must enforce the same declared-size cap as the sync path,
// including the 1-byte floor applied when the declared size is 0.

const nodeMajor = +(process.versions ? process.versions.node : "").split(".")[0] || 0;

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry DEFLATED zip whose headers declare `declaredSize`
// uncompressed bytes for the real deflate stream of `payload`. The CRC is the
// genuine CRC of `payload`, so an uncapped inflater accepts the entry as valid.
function craftDeflated(payload, declaredSize) {
    const name = Buffer.from("bomb.bin");
    const content = zlib.deflateRawSync(payload);
    const crc = Utils.crc32(payload);
    const method = 8; /* DEFLATED */
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (async size cap) - GHSA-c6fg-446q-cg94", () => {
    // 8 MB of zeros deflates to a few KB, far more than the declared size
    const BOMB = Buffer.alloc(8 * 1024 * 1024);

    describe("Inflater.inflateAsync", () => {
        it("rejects output larger than the declared size", (done) => {
            const inflater = new Methods.Inflater(zlib.deflateRawSync(BOMB), 1024);
            inflater.inflateAsync(function (data, err) {
                expect(err, "async inflate must fail once the declared size is exceeded").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("treats a declared size of 0 as a 1-byte cap", (done) => {
            const inflater = new Methods.Inflater(zlib.deflateRawSync(BOMB), 0);
            inflater.inflateAsync(function (data, err) {
                expect(err, "declared size 0 must not disable the async cap").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("calls back exactly once when the cap is exceeded", (done) => {
            const inflater = new Methods.Inflater(zlib.deflateRawSync(BOMB), 1);
            let calls = 0;
            inflater.inflateAsync(function () {
                calls++;
            });
            setTimeout(function () {
                expect(calls).to.equal(1);
                done();
            }, 200);
        });

        it("still inflates data that matches the declared size", (done) => {
            const payload = Buffer.from("hello world ".repeat(5000));
            const inflater = new Methods.Inflater(zlib.deflateRawSync(payload), payload.length);
            inflater.inflateAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            });
        });
    });

    describe("ZipEntry.getDataAsync", () => {
        it("does not inflate past an understated declared size", (done) => {
            const zip = new Zip(craftDeflated(BOMB, 1024));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err, "getDataAsync must enforce the declared-size cap like getData").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("does not inflate without limit when the declared size is 0", (done) => {
            const zip = new Zip(craftDeflated(BOMB, 0));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err, "declared size 0 must not disable the async cap").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("surfaces the cap error through readAsTextAsync", (done) => {
            const zip = new Zip(craftDeflated(BOMB, 1024));
            zip.readAsTextAsync("bomb.bin", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("still reads a genuinely empty DEFLATED entry declared as size 0", (done) => {
            const zip = new Zip(craftDeflated(Buffer.alloc(0), 0));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("still reads a DEFLATED entry whose declared size is exact", (done) => {
            const payload = Buffer.from("hello world ".repeat(5000));
            const zip = new Zip(craftDeflated(payload, payload.length));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            });
        });

        it("still reads a legitimate DEFLATED entry via readFileAsync", (done) => {
            const zip = new Zip();
            const payload = Buffer.from("hello world ".repeat(5000));
            zip.addFile("d.txt", payload);
            const round = new Zip(zip.toBuffer());
            round.readFileAsync("d.txt", function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            });
        });
    });

    describe("ZipEntry.getData (sync parity)", () => {
        it("still reads a genuinely empty DEFLATED entry declared as size 0", () => {
            const zip = new Zip(craftDeflated(Buffer.alloc(0), 0));
            expect(zip.getEntries()[0].getData().length).to.equal(0);
        });

        it("caps a declared size of 0 at 1 byte", function () {
            // zlib only honours maxOutputLength on the sync convenience API from
            // Node 15 on; older runtimes have no sync cap to compare against.
            if (nodeMajor < 15) this.skip();
            const zip = new Zip(craftDeflated(BOMB, 0));
            expect(() => zip.getEntries()[0].getData()).to.throw();
        });
    });
});
