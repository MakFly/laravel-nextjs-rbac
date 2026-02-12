import { ref, computed, type Ref } from 'vue'

export interface PaginationState {
  pageIndex: number
  pageSize: number
}

export function useTable<T>(data: Ref<T[]>, initialPageSize: number = 10) {
  const pagination = ref<PaginationState>({
    pageIndex: 0,
    pageSize: initialPageSize
  })

  const sorting = ref<{ id: string; desc: boolean }[]>([])

  const paginatedData = computed(() => {
    const start = pagination.value.pageIndex * pagination.value.pageSize
    const end = start + pagination.value.pageSize
    return data.value.slice(start, end)
  })

  const totalPages = computed(() =>
    Math.ceil(data.value.length / pagination.value.pageSize)
  )

  const canPreviousPage = computed(() => pagination.value.pageIndex > 0)
  const canNextPage = computed(() => pagination.value.pageIndex < totalPages.value - 1)

  function previousPage() {
    if (canPreviousPage.value) {
      pagination.value.pageIndex--
    }
  }

  function nextPage() {
    if (canNextPage.value) {
      pagination.value.pageIndex++
    }
  }

  function setPage(pageIndex: number) {
    if (pageIndex >= 0 && pageIndex < totalPages.value) {
      pagination.value.pageIndex = pageIndex
    }
  }

  function setPageSize(pageSize: number) {
    pagination.value.pageSize = pageSize
    pagination.value.pageIndex = 0
  }

  function exportToCSV() {
    if (data.value.length === 0) return

    const items = data.value as any[]
    const headers = Object.keys(items[0])
    const csv = [
      headers.join(','),
      ...items.map(item => headers.map(header => item[header]).join(','))
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'export.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return {
    pagination,
    sorting,
    paginatedData,
    totalPages,
    canPreviousPage,
    canNextPage,
    previousPage,
    nextPage,
    setPage,
    setPageSize,
    exportToCSV
  }
}
