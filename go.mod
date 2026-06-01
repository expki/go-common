module github.com/expki/go-common

go 1.26.3

require (
	github.com/blevesearch/bleve/v2 v2.6.0
	github.com/spf13/afero v1.15.0
)

require (
	github.com/RoaringBitmap/roaring/v2 v2.14.5 // indirect
	github.com/bits-and-blooms/bitset v1.24.2 // indirect
	github.com/blevesearch/bleve_index_api v1.3.12 // indirect
	github.com/blevesearch/geo v0.2.5 // indirect
	github.com/blevesearch/go-faiss v1.1.3 // indirect
	github.com/blevesearch/go-porterstemmer v1.0.3 // indirect
	github.com/blevesearch/gtreap v0.1.1 // indirect
	github.com/blevesearch/mmap-go v1.2.0 // indirect
	github.com/blevesearch/scorch_segment_api/v2 v2.4.7 // indirect
	github.com/blevesearch/segment v0.9.1 // indirect
	github.com/blevesearch/snowballstem v0.9.0 // indirect
	github.com/blevesearch/upsidedown_store_api v1.0.2 // indirect
	github.com/blevesearch/vellum v1.2.0 // indirect
	github.com/blevesearch/zapx/v11 v11.4.3 // indirect
	github.com/blevesearch/zapx/v12 v12.4.3 // indirect
	github.com/blevesearch/zapx/v13 v13.4.3 // indirect
	github.com/blevesearch/zapx/v14 v14.4.3 // indirect
	github.com/blevesearch/zapx/v15 v15.4.3 // indirect
	github.com/blevesearch/zapx/v16 v16.3.4 // indirect
	github.com/blevesearch/zapx/v17 v17.1.5 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/json-iterator/go v0.0.0-20171115153421-f7279a603ede // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	go.etcd.io/bbolt v1.4.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/blevesearch/bleve/v2 => github.com/expki/bleve/v2 v2.0.0-20260601001408-6dcca3e81825

replace go.etcd.io/bbolt => github.com/expki/bbolt v1.5.0-rc.0.0.20260531215528-dccadea585ba

replace github.com/couchbase/moss => github.com/expki/moss v0.3.1-0.20260531225414-59d2b052742f

replace github.com/blevesearch/goleveldb => github.com/expki/goleveldb v1.1.1-0.20260531225348-4fd0b17d74ea

replace github.com/blevesearch/zapx/v17 => github.com/expki/zapx/v17 v17.1.6-0.20260531230506-e6da921ff3d7
