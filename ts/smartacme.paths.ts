import * as path from 'path'
import * as smartfile from 'smartfile'

export let packageDir = path.join(__dirname,'../')
export let assetDir = path.join(packageDir,'assets/')
smartfile.fs.ensureDirSync(assetDir)
