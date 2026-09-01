package tool

import "testing"

// The stream a package that fails to build produces: the build events keyed by
// ImportPath, then the package-level fail event that echoes the build failure.
// go test exits 1 here exactly as it does for a failing test.
const unbuiltStream = `{"ImportPath":"example.com/m/lib [example.com/m/lib.test]","Action":"build-output","Output":"# example.com/m/lib\n"}
{"ImportPath":"example.com/m/lib [example.com/m/lib.test]","Action":"build-output","Output":"lib/lib.go:7:9: cannot use nil as Code value in return statement\n"}
{"ImportPath":"example.com/m/lib [example.com/m/lib.test]","Action":"build-fail"}
{"Action":"start","Package":"example.com/m/lib"}
{"Action":"output","Package":"example.com/m/lib","Output":"FAIL\texample.com/m/lib [build failed]\n"}
{"Action":"fail","Package":"example.com/m/lib","Elapsed":0,"FailedBuild":"example.com/m/lib [example.com/m/lib.test]"}
`

const failedStream = `{"Action":"start","Package":"example.com/m/lib"}
{"Action":"run","Package":"example.com/m/lib","Test":"TestAnswer"}
{"Action":"output","Package":"example.com/m/lib","Test":"TestAnswer","Output":"--- FAIL: TestAnswer (0.00s)\n"}
{"Action":"fail","Package":"example.com/m/lib","Test":"TestAnswer","Elapsed":0}
{"Action":"fail","Package":"example.com/m/lib","Elapsed":0.01}
`

const passedStream = `{"Action":"start","Package":"example.com/m/lib"}
{"Action":"run","Package":"example.com/m/lib","Test":"TestAnswer"}
{"Action":"pass","Package":"example.com/m/lib","Test":"TestAnswer","Elapsed":0}
{"Action":"pass","Package":"example.com/m/lib","Elapsed":0.01}
`

// A package-level failure with no named test and no failed build is a test
// binary that died: a panic, a timeout, or the injected leak TestMain. The mutant was
// noticed.
const crashedStream = `{"Action":"start","Package":"example.com/m/lib"}
{"Action":"output","Package":"example.com/m/lib","Output":"panic: boom\n"}
{"Action":"fail","Package":"example.com/m/lib","Elapsed":0.01}
`

func TestOverlayOutcomeTellsAFailedBuildFromAFailedTest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		stream string
		want   OverlayOutcome
	}{
		{"a package that did not build", unbuiltStream, OverlayNotBuilt},
		{"a test that failed", failedStream, OverlayFailed},
		{"a suite that passed", passedStream, OverlayPassed},
		{"a test binary that died", crashedStream, OverlayFailed},
		// A kill in a package that built is the evidence the run was after,
		// whatever happened to an importer that never compiled against it.
		{"a failed test beside a failed build", unbuiltStream + failedStream, OverlayFailed},
		{"a failed build after a failed test", failedStream + unbuiltStream, OverlayFailed},
		{"nothing at all", "", OverlayPassed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := overlayOutcome(tc.stream)
			if err != nil {
				t.Fatalf("overlayOutcome: %v", err)
			}
			if got != tc.want {
				t.Fatalf("overlayOutcome = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOverlayOutcomeRejectsAStreamItCannotRead(t *testing.T) {
	t.Parallel()
	if _, err := overlayOutcome("not json\n"); err == nil {
		t.Fatal("a stream that is not go test JSON was read as an outcome")
	}
}
