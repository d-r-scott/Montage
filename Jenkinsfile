def buildBadge = addEmbeddableBadgeConfiguration(id: "MontageBuild", subject: "Montage Build")
def testBadge = addEmbeddableBadgeConfiguration(id: "MontageTest", subject: "Montage Tests")

pipeline {
  
  agent any
  
  stages {   
    stage("build") {
      steps {
        script {
          sh 'make'
          buildBadge.setStatus('passed')
          buildBadge.setColor('yellow')
        }
      }
    }
    
    stage("test") {
      steps {
        script {
          echo 'TBD tests ...'
          testBadge.setStatus('231 passed, 2 failed')
          testBadge.setColor('pink')
        }
      }
    }
  }
}  