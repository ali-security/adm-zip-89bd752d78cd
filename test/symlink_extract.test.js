"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

// Regression tests for CVE-2026-76845 (symlink attack):
// sanitize() only proves that the textual entry path stays below the target
// directory. When a component of that path already exists on disk as a
// symlink (or a Windows junction) pointing outside the target, extraction used
// to follow it and write files / create folders outside the extraction root.
// Every extraction method must refuse to write through such a symlink.

describe("adm-zip - symlink extraction - CVE-2026-76845", () => {
    const base = pth.resolve("./test/xxx-symlink");
    const root = pth.join(base, "root");
    const outside = pth.join(base, "outside");
    const outsideFile = pth.join(outside, "victim.txt");
    const ORIGINAL = "original outside content";

    // Directory links use the "junction" type so Windows does not need the
    // symlink privilege; the type argument is ignored on other platforms.
    function linkDir(target, linkPath, ctx) {
        try {
            fs.symlinkSync(target, linkPath, "junction");
        } catch (e) {
            ctx.skip();
        }
    }

    function linkFile(target, linkPath, ctx) {
        try {
            fs.symlinkSync(target, linkPath, "file");
        } catch (e) {
            // creating file symlinks needs elevated privileges on Windows
            ctx.skip();
        }
    }

    function makeZip(entries) {
        const zip = new Zip();
        entries.forEach((e) => zip.addFile(e.name, e.content === undefined ? null : Buffer.from(e.content)));
        return new Zip(zip.toBuffer());
    }

    function removeLinks(dir) {
        if (!fs.existsSync(dir)) return;
        fs.readdirSync(dir).forEach((name) => {
            const p = pth.join(dir, name);
            if (isLink(p)) {
                try {
                    fs.unlinkSync(p);
                } catch (e) {
                    fs.rmdirSync(p);
                }
            } else if (fs.lstatSync(p).isDirectory()) {
                removeLinks(p);
            }
        });
    }

    function isLink(p) {
        try {
            return fs.lstatSync(p).isSymbolicLink();
        } catch (e) {
            return false;
        }
    }

    beforeEach(() => {
        removeLinks(base);
        rimraf.sync(base);
        fs.mkdirSync(root, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
        fs.writeFileSync(outsideFile, ORIGINAL);
    });

    afterEach(() => {
        // drop the links first so cleanup never walks into the outside folder
        removeLinks(base);
        rimraf.sync(base);
    });

    describe("extractAllTo", () => {
        it("rejects a file entry written through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([{ name: "link/evil.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(/file in the way/);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("rejects a file entry written through a nested symlinked directory", function () {
            fs.mkdirSync(pth.join(root, "a"));
            linkDir(outside, pth.join(root, "a", "link"), this);
            const zip = makeZip([{ name: "a/link/evil.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(/file in the way/);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("rejects a directory entry created through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([{ name: "link/sub/" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(/file in the way/);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
        });

        it("rejects overwriting a file that is a symlink to a file outside the target", function () {
            linkFile(outsideFile, pth.join(root, "victim.txt"), this);
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(/file in the way/);
            expect(fs.readFileSync(outsideFile, "utf8")).to.equal(ORIGINAL);
        });

        it("still extracts into a target directory that is itself a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(root, rootLink, this);
            const zip = makeZip([
                { name: "a/" },
                { name: "a/b.txt", content: "hello" }
            ]);

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("hello");
        });

        it("still extracts into pre-existing real directories", () => {
            fs.mkdirSync(pth.join(root, "a"));
            const zip = makeZip([{ name: "a/b/c.txt", content: "hello" }]);

            zip.extractAllTo(root, true);
            expect(fs.readFileSync(pth.join(root, "a", "b", "c.txt"), "utf8")).to.equal("hello");
        });
    });

    describe("extractEntryTo", () => {
        it("rejects a file entry written through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([{ name: "link/evil.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("link/evil.txt", root, true, true)).to.throw(/file in the way/);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("rejects overwriting a file that is a symlink to a file outside the target", function () {
            linkFile(outsideFile, pth.join(root, "victim.txt"), this);
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("victim.txt", root, true, true)).to.throw(/file in the way/);
            expect(fs.readFileSync(outsideFile, "utf8")).to.equal(ORIGINAL);
        });

        it("rejects children of a directory entry written through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([
                { name: "link/" },
                { name: "link/evil.txt", content: "pwned" }
            ]);

            expect(() => zip.extractEntryTo("link/", root, true, true)).to.throw(/file in the way/);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("still extracts an entry into a target directory that is itself a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(root, rootLink, this);
            const zip = makeZip([{ name: "a/b.txt", content: "hello" }]);

            zip.extractEntryTo("a/b.txt", rootLink, true, true);
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("hello");
        });
    });

    describe("extractAllToAsync", () => {
        it("rejects a file entry written through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([{ name: "link/evil.txt", content: "pwned" }]);

            return zip.extractAllToAsync(root, true).then(
                () => {
                    throw new Error("extraction through a symlink should have failed");
                },
                (err) => {
                    expect(err.message).to.match(/file in the way/);
                    expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
                }
            );
        });

        it("rejects overwriting a file that is a symlink to a file outside the target", function () {
            linkFile(outsideFile, pth.join(root, "victim.txt"), this);
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            return zip.extractAllToAsync(root, true).then(
                () => {
                    throw new Error("extraction through a symlink should have failed");
                },
                (err) => {
                    expect(err.message).to.match(/file in the way/);
                    expect(fs.readFileSync(outsideFile, "utf8")).to.equal(ORIGINAL);
                }
            );
        });

        it("rejects a directory entry created through a symlinked directory", function () {
            linkDir(outside, pth.join(root, "link"), this);
            const zip = makeZip([{ name: "link/sub/" }]);

            return zip.extractAllToAsync(root, true).then(
                () => {
                    throw new Error("extraction through a symlink should have failed");
                },
                (err) => {
                    expect(err.message).to.match(/Unable to create folder/);
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
                }
            );
        });

        it("still extracts into a target directory that is itself a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(root, rootLink, this);
            const zip = makeZip([
                { name: "a/" },
                { name: "a/b.txt", content: "hello" }
            ]);

            return zip.extractAllToAsync(rootLink, true).then(() => {
                expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("hello");
            });
        });
    });

    describe("Utils.assertPathSafe", () => {
        const utils = new Utils();

        it("throws when a component below the root is a symlink", function () {
            linkDir(outside, pth.join(root, "link"), this);
            expect(() => utils.assertPathSafe(root, pth.join(root, "link", "x", "y.txt"))).to.throw(/file in the way/);
        });

        it("accepts paths whose components do not exist yet", () => {
            expect(() => utils.assertPathSafe(root, pth.join(root, "new", "dir", "file.txt"))).to.not.throw();
        });

        it("accepts the root itself and real directories below it", () => {
            fs.mkdirSync(pth.join(root, "real"));
            expect(() => utils.assertPathSafe(root, root)).to.not.throw();
            expect(() => utils.assertPathSafe(root, pth.join(root, "real", "file.txt"))).to.not.throw();
        });
    });
});
